import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
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
