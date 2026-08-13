import assert from "node:assert/strict";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the published runtime executes without node_modules and reports its release version", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "npm-artifact-"));
  const repository = await mkdtemp(join(tmpdir(), "npm-target-"));
  const entrypoint = join(artifact, "dist", "index.js");
  const schema = join(artifact, "schemas", "adversary.review.v1.schema.json");

  await mkdir(dirname(entrypoint), { recursive: true });
  await mkdir(dirname(schema), { recursive: true });
  await copyFile(join(projectRoot, "dist", "index.js"), entrypoint);
  await copyFile(join(projectRoot, "schemas", "adversary.review.v1.schema.json"), schema);
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["']@adversarylabs\/sdk["']/);

  const runtime = await import(pathToFileURL(entrypoint).href) as {
    createApp(): {
      run(options: { input: unknown }): Promise<{
        adversary: { name: string; version?: string };
        findings: unknown[];
      }>;
    };
  };
  const result = await runtime.createApp().run({ input: { source: { path: repository } } });
  assert.equal(result.adversary.name, "npm");
  assert.equal(result.adversary.version, "0.0.9");
  assert.deepEqual(result.findings, []);
});
