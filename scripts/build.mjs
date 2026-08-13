import { build } from "esbuild";
import { copyFile, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  banner: {
    js: "import { createRequire as __adversaryCreateRequire } from 'node:module'; import * as __adversaryUrl from 'node:url'; import * as __adversaryPath from 'node:path'; const require = __adversaryCreateRequire(import.meta.url); const __filename = __adversaryUrl.fileURLToPath(import.meta.url); const __dirname = __adversaryPath.dirname(__filename);",
  },
});

await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);
