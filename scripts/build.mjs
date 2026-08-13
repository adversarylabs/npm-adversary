import { build } from "esbuild";
import { copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

const result = await build({
  entryPoints: ["src/index.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  outfile: "dist/index.js",
  metafile: true,
  banner: {
    js: "import { createRequire as __adversaryCreateRequire } from 'node:module'; import * as __adversaryUrl from 'node:url'; import * as __adversaryPath from 'node:path'; const require = __adversaryCreateRequire(import.meta.url); const __filename = __adversaryUrl.fileURLToPath(import.meta.url); const __dirname = __adversaryPath.dirname(__filename);",
  },
});

function packageDirectory(input) {
  const segments = input.replaceAll("\\", "/").split("/");
  const nodeModules = segments.lastIndexOf("node_modules");
  if (nodeModules === -1) return undefined;

  const first = segments[nodeModules + 1];
  const packageSegments = first?.startsWith("@") ? 2 : 1;
  if (!first || segments.length <= nodeModules + packageSegments) {
    throw new Error(`Cannot identify bundled package for ${input}`);
  }
  return segments.slice(0, nodeModules + 1 + packageSegments).join("/");
}

const packageDirectories = [...new Set(
  Object.keys(result.metafile.inputs).map(packageDirectory).filter(Boolean),
)].sort();
const notices = [
  "THIRD-PARTY SOFTWARE NOTICES",
  "",
  "This artifact bundles the following packages. The notices are generated from",
  "the exact esbuild metafile inputs; the build fails if a package has no notice.",
];

for (const directory of packageDirectories) {
  const metadata = JSON.parse(await readFile(`${directory}/package.json`, "utf8"));
  if (typeof metadata.name !== "string" || typeof metadata.version !== "string") {
    throw new Error(`Bundled package at ${directory} lacks a name or version`);
  }
  const licenseFiles = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && /(?:^licen[cs]e|^copying|notice)/i.test(entry.name))
    .map(({ name }) => name)
    .sort();
  if (licenseFiles.length === 0) {
    throw new Error(`Bundled package ${metadata.name}@${metadata.version} has no license notice`);
  }

  notices.push("", "=".repeat(80), `Package: ${metadata.name}@${metadata.version}`);
  for (const filename of licenseFiles) {
    notices.push("", `--- ${filename} ---`, "", (await readFile(`${directory}/${filename}`, "utf8")).trimEnd());
  }
}

await writeFile("THIRD_PARTY_LICENSES.txt", `${notices.join("\n")}\n`);

await mkdir("schemas", { recursive: true });
await copyFile(
  "node_modules/@adversarylabs/sdk/schemas/adversary.review.v1.schema.json",
  "schemas/adversary.review.v1.schema.json",
);
