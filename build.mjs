import { build } from "esbuild";
import { mkdir, rm, stat, readFile, writeFile } from "fs/promises";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { minify as minifyHtml } from "html-minifier-terser";
import { minify as minifyJs } from "terser";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const entry = resolve(__dirname, "pow.js");
const templatePath = resolve(__dirname, "template.html");
const outdir = resolve(__dirname, "dist");
const outfile = resolve(outdir, "pow_snippet.js");

console.log("Reading HTML template...");
const templateContent = await readFile(templatePath, "utf-8");

console.log("Minifying HTML template...");
const minifiedHtml = await minifyHtml(templateContent, {
  collapseWhitespace: true,
  removeComments: true,
  removeRedundantAttributes: true,
  removeEmptyAttributes: true,
  minifyCSS: true,
  minifyJS: {
    compress: {
      dead_code: true,
      drop_console: false,
      drop_debugger: true,
      keep_classnames: false,
      keep_fnames: false,
    },
    mangle: {
      toplevel: true,
    },
  },
  minifyURLs: true,
  removeAttributeQuotes: true,
  removeOptionalTags: false,
  removeScriptTypeAttributes: true,
  removeStyleLinkTypeAttributes: true,
  useShortDoctype: true,
  keepClosingSlash: false,
  caseSensitive: false,
  conservativeCollapse: false,
  quoteCharacter: '"',
});

console.log(
  `Template: ${templateContent.length} → ${minifiedHtml.length} bytes (${Math.round(
    (1 - minifiedHtml.length / templateContent.length) * 100
  )}% reduction)`
);

await mkdir(outdir, { recursive: true });
await rm(outfile, { force: true });

await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  format: "esm",
  target: "es2022",
  platform: "neutral",
  minify: true,
  legalComments: "none",
  charset: "ascii",
  define: {
    __HTML_TEMPLATE__: JSON.stringify(minifiedHtml),
  },
});

const built = await readFile(outfile, "utf-8");
const terserResult = await minifyJs(built, {
  ecma: 2022,
  module: true,
  compress: { passes: 3, toplevel: true },
  mangle: { toplevel: true },
  format: { ascii_only: true },
});
if (terserResult && typeof terserResult.code === "string") {
  await writeFile(outfile, terserResult.code);
}

const { size } = await stat(outfile);
const limit = 32 * 1024;
const status = size <= limit ? "OK" : "OVER";
console.log(`Built snippet: ${outfile} (${size} bytes, ${status} ${limit} bytes)`);
if (size > limit) process.exitCode = 1;
