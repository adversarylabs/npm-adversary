import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { loadInScopeSources } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);
const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
    const sources = [];
    for (const file of scoped) {
        const change = wholeTarget || file.status === "repository"
            ? { changedLines: new Set(), status: "repository" }
            : await changedSource(ctx, file.path);
        sources.push({
            path: file.path,
            source: file.content,
            inScope: true,
            changedLines: change.changedLines,
            status: change.status,
        });
    }
    ctx.summary.files_scanned = sources.length;
    const needsRepositoryContext = ctx.change !== null && ctx.change.scanMode === "changed";
    const contextSources = needsRepositoryContext
        ? await loadDependencyMetadataContext(ctx.repoPath, sources)
        : sources;
    const detections = spec.rules.flatMap((rule) => rule.match.kind === "direct-dependency-drift"
        ? findDirectDependencyDrift(rule, contextSources)
        : evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    if (match.kind === "direct-dependency-drift")
        return [];
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locateEligible(file, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locateEligible(file, match.pattern, match.anchors);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
async function loadDependencyMetadataContext(repoPath, scoped) {
    const byPath = new Map(scoped.map((source) => [source.path, source]));
    const context = await loadInScopeSources(repoPath, null, {
        include: (path) => /(^|\/)(?:package|package-lock|npm-shrinkwrap)\.json$/.test(path),
        limit: MAX_FILES,
    });
    for (const source of context) {
        if (!byPath.has(source.path)) {
            byPath.set(source.path, {
                path: source.path,
                source: source.content,
                inScope: false,
                changedLines: new Set(),
                status: "repository",
            });
        }
    }
    return [...byPath.values()];
}
function findDirectDependencyDrift(rule, sources) {
    const byPath = new Map(sources.map((source) => [source.path, source]));
    const detections = [];
    const candidates = sources.filter((source) => /(^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(source.path));
    const shrinkwrapRoots = new Set(candidates.filter((source) => source.path.endsWith("npm-shrinkwrap.json")).map((source) => dirname(source.path)));
    const lockfiles = candidates.filter((source) => source.path.endsWith("npm-shrinkwrap.json") || !shrinkwrapRoots.has(dirname(source.path)));
    for (const lockfile of lockfiles) {
        const root = dirname(lockfile.path);
        let lock;
        try {
            lock = asRecord(JSON.parse(lockfile.source));
        }
        catch {
            continue;
        }
        const packages = asRecord(lock?.packages);
        if (!packages)
            continue;
        for (const [lockKey, rawLockPackage] of Object.entries(packages)) {
            if (lockKey.includes("node_modules"))
                continue;
            const manifestPath = lockKey === "" ? joinPath(root, "package.json") : joinPath(root, `${lockKey}/package.json`);
            const manifestSource = byPath.get(manifestPath);
            if (!manifestSource)
                continue;
            if (!lockfile.inScope && !manifestSource.inScope)
                continue;
            let manifest;
            try {
                manifest = asRecord(JSON.parse(manifestSource.source));
            }
            catch {
                continue;
            }
            const lockPackage = asRecord(rawLockPackage);
            if (!manifest || !lockPackage)
                continue;
            for (const field of DEPENDENCY_FIELDS) {
                const manifestDependencies = stringMap(manifest[field]);
                const lockedDependencies = stringMap(lockPackage[field]);
                const names = [...new Set([...Object.keys(manifestDependencies), ...Object.keys(lockedDependencies)])].sort();
                for (const name of names) {
                    const declared = manifestDependencies[name];
                    const locked = lockedDependencies[name];
                    if (declared === locked)
                        continue;
                    const change = declared === undefined ? "removed" : locked === undefined ? "missing" : "changed";
                    const index = declared === undefined ? locateLockPackageKey(lockfile.source, lockKey, field, name) : locateJsonKey(manifestSource.source, name, field);
                    const evidenceSource = declared === undefined ? lockfile : manifestSource;
                    detections.push({
                        rule,
                        file: evidenceSource.path,
                        ...locateFromIndex(evidenceSource.source, index),
                        label: `${name} ${change} between ${manifestPath} and ${lockfile.path}`,
                        data: { dependency: name, dependencyType: field, manifestSpec: declared ?? null, lockfileSpec: locked ?? null, manifest: manifestPath, lockfile: lockfile.path, drift: change },
                    });
                }
            }
        }
    }
    return detections;
}
function dirname(path) {
    const index = path.lastIndexOf("/");
    return index < 0 ? "" : path.slice(0, index);
}
function joinPath(root, path) {
    return root ? `${root}/${path}` : path;
}
function asRecord(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}
function stringMap(value) {
    const record = asRecord(value);
    if (!record)
        return {};
    return Object.fromEntries(Object.entries(record).filter((entry) => typeof entry[1] === "string"));
}
function locateJsonKey(source, key, field) {
    const fieldIndex = source.indexOf(JSON.stringify(field));
    const keyIndex = source.indexOf(JSON.stringify(key), Math.max(0, fieldIndex));
    return keyIndex >= 0 ? keyIndex : Math.max(0, fieldIndex);
}
function locateLockPackageKey(source, lockKey, field, key) {
    const packagesIndex = source.indexOf('"packages"');
    const packageIndex = source.indexOf(`${JSON.stringify(lockKey)}: {`, Math.max(0, packagesIndex));
    const fieldIndex = source.indexOf(JSON.stringify(field), Math.max(0, packageIndex));
    const keyIndex = source.indexOf(JSON.stringify(key), Math.max(0, fieldIndex));
    return keyIndex >= 0 ? keyIndex : Math.max(0, fieldIndex);
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locateEligible(file, expression, anchors) {
    const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
    for (const match of file.source.matchAll(new RegExp(expression.pattern, flags))) {
        if (match.index === undefined || match[0] === "")
            continue;
        const line = file.status === "modified" && anchors !== undefined
            ? eligibleSemanticAnchor(file, match.index, match[0], anchors)
            : eligibleRangeAnchor(file, match.index, match.index + match[0].length);
        if (line !== undefined)
            return locateFromLine(file.source, line);
    }
    return undefined;
}
function eligibleSemanticAnchor(file, offset, matchedSource, anchors) {
    let eligible;
    for (const anchor of anchors) {
        const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
        for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
            if (match.index === undefined || match[0] === "")
                continue;
            const line = eligibleRangeAnchor(file, offset + match.index, offset + match.index + match[0].length);
            if (line !== undefined && (eligible === undefined || line < eligible))
                eligible = line;
        }
    }
    return eligible;
}
function eligibleRangeAnchor(file, start, end) {
    const startLine = lineAt(file.source, start);
    if (file.status !== "modified")
        return startLine;
    const endLine = lineAt(file.source, Math.max(start, end - 1));
    for (let line = startLine; line <= endLine; line += 1) {
        if (file.changedLines.has(line))
            return line;
    }
    return undefined;
}
function lineAt(source, index) {
    return source.slice(0, index).split(/\r?\n/).length;
}
function locateFromLine(source, line) {
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
async function changedSource(ctx, path) {
    const base = ctx.change?.baseRef;
    if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
        return { changedLines: new Set(), status: "added" };
    }
    const args = ["diff", "--unified=0", base];
    const head = ctx.change?.headRef;
    if (head !== undefined && !ctx.change?.worktree)
        args.push(head);
    args.push("--", path);
    const patch = await gitOutput(ctx.repoPath, args);
    return { changedLines: changedLineNumbers(patch), status: "modified" };
}
async function existsAtRevision(repoPath, revision, path) {
    try {
        await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
            maxBuffer: 1024 * 1024,
        });
        return true;
    }
    catch {
        return false;
    }
}
async function gitOutput(repoPath, args) {
    const result = await execute("git", ["-C", repoPath, ...args], {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    return result.stdout;
}
function changedLineNumbers(patch) {
    const lines = new Set();
    for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
        const start = Number(match[1]);
        const count = match[2] === undefined ? 1 : Number(match[2]);
        for (let line = start; line < start + count; line += 1)
            lines.add(line);
    }
    return lines;
}
function locateFromIndex(source, index) {
    const line = source.slice(0, index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
