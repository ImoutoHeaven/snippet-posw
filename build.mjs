import { build } from "esbuild";
import { mkdir, rm, stat, readFile, writeFile } from "fs/promises";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { minify as minifyHtml } from "html-minifier-terser";
import { minify as minifyJs } from "terser";
import { buildCompiledConfig } from "./lib/build-config.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const powCore1Entry = resolve(__dirname, "pow-core-1.js");
const powCore2Entry = resolve(__dirname, "pow-core-2.js");
const powConfigEntry = resolve(__dirname, "pow-config.js");
const templatePath = resolve(__dirname, "template.html");
const outdir = resolve(__dirname, "dist");
const powLegacyOutfile = resolve(outdir, "pow_snippet.js");
const powConfigOutfile = resolve(outdir, "pow_config_snippet.js");
const powCore1Outfile = resolve(outdir, "pow_core1_snippet.js");
const powCore2Outfile = resolve(outdir, "pow_core2_snippet.js");


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

const compiledConfig = await buildCompiledConfig(powConfigEntry);

await mkdir(outdir, { recursive: true });
await rm(powLegacyOutfile, { force: true });
await rm(powConfigOutfile, { force: true });
await rm(powCore1Outfile, { force: true });
await rm(powCore2Outfile, { force: true });

const buildSnippet = async ({ entryPoints, outfile, define }) => {
  await build({
    entryPoints,
    outfile,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "neutral",
    minify: true,
    legalComments: "none",
    charset: "ascii",
    define,
  });
};

const minifyAndCheck = async (path) => {
  const built = await readFile(path, "utf-8");
  const terserResult = await minifyJs(built, {
    ecma: 2022,
    module: true,
    compress: {
      passes: 3,
      toplevel: true,
      unsafe: true,
      unsafe_arrows: true,
      unsafe_comps: true,
      unsafe_Function: true,
      unsafe_math: true,
      unsafe_methods: true,
      unsafe_proto: true,
      unsafe_regexp: true,
      unsafe_undefined: true,
      unsafe_symbols: true,
    },
    mangle: { toplevel: true },
    format: { ascii_only: true },
  });
  if (terserResult && typeof terserResult.code === "string") {
    await writeFile(path, terserResult.code);
  }

  const { size } = await stat(path);
  const limit = 32 * 1024;
  const status = size <= limit ? "OK" : "OVER";
  console.log(`Built snippet: ${path} (${size} bytes, ${status} ${limit} bytes)`);
  if (size > limit) process.exitCode = 1;
};

await buildSnippet({
  entryPoints: [powConfigEntry],
  outfile: powConfigOutfile,
  define: {
    __COMPILED_CONFIG__: compiledConfig,
  },
});
await buildSnippet({
  entryPoints: [powCore1Entry],
  outfile: powCore1Outfile,
  define: {
    __HTML_TEMPLATE__: JSON.stringify(minifiedHtml),
  },
});
await buildSnippet({
  entryPoints: [powCore2Entry],
  outfile: powCore2Outfile,
  define: {
    __HTML_TEMPLATE__: JSON.stringify(minifiedHtml),
  },
});

await minifyAndCheck(powConfigOutfile);
await minifyAndCheck(powCore1Outfile);
await minifyAndCheck(powCore2Outfile);
