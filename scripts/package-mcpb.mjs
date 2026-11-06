import { build } from "esbuild";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const stage = path.join(root, "mcpb-build");

await fs.rm(stage, { recursive: true, force: true });
await fs.mkdir(path.join(stage, "server"), { recursive: true });
await fs.copyFile(path.join(root, "mcpb", "manifest.json"), path.join(stage, "manifest.json"));
await fs.writeFile(path.join(stage, "package.json"), JSON.stringify({ private: true, type: "module" }) + "\n", "utf8");

await build({
  entryPoints: [path.join(root, "dist", "stdio.js")],
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node20",
  outfile: path.join(stage, "server", "index.js"),
  legalComments: "none",
  plugins: [
    {
      name: "stub-dotenv",
      setup(buildContext) {
        buildContext.onResolve({ filter: /^dotenv(\/.*)?$/ }, (args) => ({
          path: args.path,
          namespace: "stub-dotenv",
        }));
        buildContext.onLoad({ filter: /.*/, namespace: "stub-dotenv" }, () => ({
          contents: "export default {}; export const config = () => ({});",
        }));
      },
    },
  ],
});

const entry = await fs.stat(path.join(stage, "server", "index.js"));
if (!entry.isFile() || entry.size === 0) throw new Error("MCPB staging bundle was not created.");
