import { readFile, readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { loadInScopeSources, type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;

interface SourceFile { path: string; source: string; inScope: boolean }
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }
const DEPENDENCY_FIELDS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = scoped.map((file) => ({ path: file.path, source: file.content, inScope: true }));
  ctx.summary.files_scanned = sources.length;

  const needsRepositoryContext = ctx.change !== null && ctx.change.scanMode === "changed";
  const contextSources = needsRepositoryContext
    ? await loadDependencyMetadataContext(ctx.repoPath, sources)
    : sources;
  const detections = spec.rules.flatMap((rule) => rule.match.kind === "direct-dependency-drift"
    ? findDirectDependencyDrift(rule, contextSources)
    : evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }
  if (match.kind === "direct-dependency-drift") return [];

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locate(file.source, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locate(file.source, match.pattern);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

async function loadDependencyMetadataContext(repoPath: string, scoped: SourceFile[]): Promise<SourceFile[]> {
  const byPath = new Map(scoped.map((source) => [source.path, source]));
  const context = await loadInScopeSources(repoPath, null, {
    include: (path) => /(^|\/)(?:package|package-lock|npm-shrinkwrap)\.json$/.test(path),
    limit: MAX_FILES,
  });
  for (const source of context) {
    if (!byPath.has(source.path)) byPath.set(source.path, { path: source.path, source: source.content, inScope: false });
  }
  return [...byPath.values()];
}

function findDirectDependencyDrift(rule: RuleSpec, sources: SourceFile[]): Detection[] {
  const byPath = new Map(sources.map((source) => [source.path, source]));
  const detections: Detection[] = [];
  const candidates = sources.filter((source) => /(^|\/)(?:package-lock|npm-shrinkwrap)\.json$/.test(source.path));
  const shrinkwrapRoots = new Set(candidates.filter((source) => source.path.endsWith("npm-shrinkwrap.json")).map((source) => dirname(source.path)));
  const lockfiles = candidates.filter((source) => source.path.endsWith("npm-shrinkwrap.json") || !shrinkwrapRoots.has(dirname(source.path)));

  for (const lockfile of lockfiles) {
    const root = dirname(lockfile.path);
    let lock: Record<string, unknown> | undefined;
    try { lock = asRecord(JSON.parse(lockfile.source)); } catch { continue; }
    const packages = asRecord(lock?.packages);
    if (!packages) continue;

    for (const [lockKey, rawLockPackage] of Object.entries(packages)) {
      if (lockKey.includes("node_modules")) continue;
      const manifestPath = lockKey === "" ? joinPath(root, "package.json") : joinPath(root, `${lockKey}/package.json`);
      const manifestSource = byPath.get(manifestPath);
      if (!manifestSource) continue;
      if (!lockfile.inScope && !manifestSource.inScope) continue;
      let manifest: Record<string, unknown> | undefined;
      try { manifest = asRecord(JSON.parse(manifestSource.source)); } catch { continue; }
      const lockPackage = asRecord(rawLockPackage);
      if (!manifest || !lockPackage) continue;

      for (const field of DEPENDENCY_FIELDS) {
        const manifestDependencies = stringMap(manifest[field]);
        const lockedDependencies = stringMap(lockPackage[field]);
        const names = [...new Set([...Object.keys(manifestDependencies), ...Object.keys(lockedDependencies)])].sort();
        for (const name of names) {
          const declared = manifestDependencies[name];
          const locked = lockedDependencies[name];
          if (declared === locked) continue;
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

function dirname(path: string): string {
  const index = path.lastIndexOf("/");
  return index < 0 ? "" : path.slice(0, index);
}

function joinPath(root: string, path: string): string {
  return root ? `${root}/${path}` : path;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function stringMap(value: unknown): Record<string, string> {
  const record = asRecord(value);
  if (!record) return {};
  return Object.fromEntries(Object.entries(record).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

function locateJsonKey(source: string, key: string, field: string): number {
  const fieldIndex = source.indexOf(JSON.stringify(field));
  const keyIndex = source.indexOf(JSON.stringify(key), Math.max(0, fieldIndex));
  return keyIndex >= 0 ? keyIndex : Math.max(0, fieldIndex);
}

function locateLockPackageKey(source: string, lockKey: string, field: string, key: string): number {
  const packagesIndex = source.indexOf('"packages"');
  const packageIndex = source.indexOf(`${JSON.stringify(lockKey)}: {`, Math.max(0, packagesIndex));
  const fieldIndex = source.indexOf(JSON.stringify(field), Math.max(0, packageIndex));
  const keyIndex = source.indexOf(JSON.stringify(key), Math.max(0, fieldIndex));
  return keyIndex >= 0 ? keyIndex : Math.max(0, fieldIndex);
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locate(source: string, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const match = new RegExp(expression.pattern, expression.flags).exec(source);
  if (match?.index === undefined) return undefined;
  const line = source.slice(0, match.index).split(/\r?\n/).length;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

function locateFromIndex(source: string, index: number): { line: number; snippet: string } {
  const line = source.slice(0, index).split(/\r?\n/).length;
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
