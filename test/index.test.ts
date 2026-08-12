import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const scopedReview = (path: string, changedFiles: string[]) => createApp().run({
  input: {
    source: { path },
    change: { type: "diff", base_ref: "base", head_ref: "head", scan_mode: "changed", changed_files: changedFiles },
  },
  includeRawObservations: true,
});
const ruleCases = [{"key": "lifecycle-remote-exec", "id": "npm.lifecycle-remote-exec"}, {"key": "lifecycle-download", "id": "npm.lifecycle-download"}, {"key": "lifecycle-obfuscated", "id": "npm.lifecycle-obfuscated"}, {"key": "script-curl-pipe", "id": "npm.script-curl-pipe"}, {"key": "publish-config-insecure-registry", "id": "npm.publish-config-insecure-registry"}, {"key": "auto-update-no-cooldown", "id": "npm.auto-update-no-cooldown"}, {"key": "direct-dependency-lock-drift", "id": "npm.direct-dependency-lock-drift"}, {"key": "unbounded-dependency", "id": "npm.unbounded-dependency"}, {"key": "missing-lockfile", "id": "npm.missing-lockfile"}, {"key": "git-dependency", "id": "npm.git-dependency"}];

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("direct dependency drift distinguishes additions, changes, removals, and workspaces", async () => {
  const output = await review("rules/direct-dependency-lock-drift/vulnerable", true);
  const observations = output.rawObservations?.filter((item) => item.ruleId === "npm.direct-dependency-lock-drift") ?? [];
  assert.deepEqual(observations.map((item) => item.evidence?.drift).sort(), ["changed", "missing", "missing", "removed"]);
  assert.deepEqual(observations.map((item) => item.evidence?.dependency).sort(), ["added-package", "changed-package", "react", "removed-package"]);
});

test("legacy v1 lockfiles stay out of the v2/v3 packages-map rule", async () => {
  const output = await review("regressions/lockfile-v1-clean");
  assert.equal(output.findings.some((finding) => finding.ruleId === "npm.direct-dependency-lock-drift"), false);
});

test("manifest-only scope compares the unchanged lockfile", async () => {
  const root = await scopedDriftRepository();
  const output = await scopedReview(root, ["package.json"]);
  const observations = output.rawObservations?.filter((item) => item.ruleId === "npm.direct-dependency-lock-drift") ?? [];
  assert.deepEqual(observations.map((item) => item.evidence?.dependency), ["manifest-only"]);
});

test("lockfile-only scope compares the unchanged manifest", async () => {
  const root = await scopedDriftRepository();
  const output = await scopedReview(root, ["package-lock.json"]);
  const observations = output.rawObservations?.filter((item) => item.ruleId === "npm.direct-dependency-lock-drift") ?? [];
  assert.deepEqual(observations.map((item) => item.evidence?.dependency), ["manifest-only"]);
});

test("unrelated out-of-scope drift is context only", async () => {
  const root = await scopedDriftRepository();
  await mkdir(join(root, "packages", "unrelated"), { recursive: true });
  await writeFile(join(root, "packages", "unrelated", "package.json"), JSON.stringify({ name: "unrelated" }, null, 2));
  const output = await scopedReview(root, ["packages/unrelated/package.json"]);
  assert.equal(output.findings.some((finding) => finding.ruleId === "npm.direct-dependency-lock-drift"), false);
});

test("an unrelated edit does not surface a legacy direct finding", async () => {
  const legacy = "registry=http://registry.example.test/\n";
  const root = await gitRepository({ ".npmrc": legacy });
  try {
    await writeFile(join(root, ".npmrc"), `${legacy}# registry owner: platform\n`);
    const output = await changedReview(root, [".npmrc"]);
    assert.equal(
      output.findings.some((finding) => finding.ruleId === "npm.publish-config-insecure-registry"),
      false,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("direct matching continues past a legacy occurrence", async () => {
  const legacy = "registry=http://legacy.example.test/\n";
  const root = await gitRepository({ ".npmrc": legacy });
  try {
    await writeFile(join(root, ".npmrc"), `${legacy}@scope:registry=http://new.example.test/\n`);
    const output = await changedReview(root, [".npmrc"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "npm.publish-config-insecure-registry",
    );
    assert.equal(observation?.location?.line, 2);
    assert.equal(observation?.location?.snippet, "@scope:registry=http://new.example.test/");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("missing-content rules ignore unchanged legacy triggers", async () => {
  const original = [
    "{",
    '  "automerge": true,',
    '  "labels": ["dependencies"]',
    "}",
    "",
  ].join("\n");
  const root = await gitRepository({ "renovate.json": original });
  try {
    await writeFile(
      join(root, "renovate.json"),
      original.replace('"dependencies"', '"dependencies", "automated"'),
    );
    const output = await changedReview(root, ["renovate.json"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "npm.auto-update-no-cooldown"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("missing-content matching continues to a changed trigger", async () => {
  const original = [
    "{",
    '  "automerge": true,',
    '  "packageRules": []',
    "}",
    "",
  ].join("\n");
  const root = await gitRepository({ "renovate.json": original });
  try {
    await writeFile(
      join(root, "renovate.json"),
      [
        "{",
        '  "automerge": true,',
        '  "packageRules": [',
        '    { "matchManagers": ["npm"], "automerge": true }',
        "  ]",
        "}",
        "",
      ].join("\n"),
    );
    const output = await changedReview(root, ["renovate.json"]);
    const observation = output.rawObservations?.find(
      (item) => item.ruleId === "npm.auto-update-no-cooldown",
    );
    assert.equal(observation?.location?.line, 4);
    assert.equal(observation?.location?.snippet, '{ "matchManagers": ["npm"], "automerge": true }');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("nearby safe dependency edits do not count as semantic anchors", async () => {
  const manifest = (safe: boolean) => [
    "{",
    '  "dependencies": {',
    ...(safe ? ['    "safe": "^1.0.0",'] : []),
    '    "legacy": "*"',
    "  }",
    "}",
    "",
  ].join("\n");
  const root = await gitRepository({ "package.json": manifest(false) });
  try {
    await writeFile(join(root, "package.json"), manifest(true));
    const output = await changedReview(root, ["package.json"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "npm.unbounded-dependency"), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("new package manifests remain fully eligible", async () => {
  const root = await gitRepository({ "README.md": "# package\n" });
  try {
    await writeFile(join(root, "package.json"), '{\n  "dependencies": {\n    "new-risk": "*"\n  }\n}\n');
    const output = await changedReview(root, ["package.json"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "npm.unbounded-dependency"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("missing-lockfile remains holistic in changed scope", async () => {
  const root = await gitRepository({ "package.json": '{ "name": "unlocked" }\n', "README.md": "# package\n" });
  try {
    await writeFile(join(root, "README.md"), "# renamed package\n");
    const output = await changedReview(root, ["README.md"]);
    assert.equal(output.findings.some((finding) => finding.ruleId === "npm.missing-lockfile"), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "npm");
});

async function scopedDriftRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "npm-lock-scope-"));
  await writeFile(join(root, "package.json"), JSON.stringify({ name: "scope-test", dependencies: { "manifest-only": "^2.0.0" } }, null, 2));
  await writeFile(join(root, "package-lock.json"), JSON.stringify({
    name: "scope-test",
    lockfileVersion: 3,
    packages: { "": { name: "scope-test", dependencies: { "manifest-only": "^1.0.0" } } },
  }, null, 2));
  return root;
}

async function changedReview(root: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: root },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
    includeRawObservations: true,
  });
}

async function gitRepository(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "npm-adversary-git-"));
  await execute("git", ["init", "--quiet", root]);
  await execute("git", ["-C", root, "config", "user.email", "tests@example.com"]);
  await execute("git", ["-C", root, "config", "user.name", "Tests"]);
  for (const [path, content] of Object.entries(files)) {
    await writeFile(join(root, path), content);
  }
  await execute("git", ["-C", root, "add", "."]);
  await execute("git", ["-C", root, "commit", "--quiet", "-m", "baseline"]);
  return root;
}
