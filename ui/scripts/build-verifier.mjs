#!/usr/bin/env node
/**
 * Build the public evidence verifier as ONE self-contained HTML file: public/verify.html
 * (served at /verify by Firebase Hosting's cleanUrls). See docs/specs/public-verify-page.md.
 *
 * - JS: verifier/entry.tsx bundled by Vite (already a dev dependency via vitest) into an IIFE.
 * - CSS: app/globals.css through Tailwind, scanning only the verifier's sources.
 * - Trust anchor: the api's pinned TSA root (api/app/assets/digicert_trusted_root_g4.pem) is
 *   inlined at build time - one source of truth, nothing fetched at runtime.
 * - CSP: a <meta> policy allowing only this exact inline script + style (by sha256) and no
 *   network at all, so the "no network calls" promise is enforced by the browser, and holds for
 *   a saved copy too.
 *
 * Usage: node scripts/build-verifier.mjs [--out <file>]
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import postcss from "postcss";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";
import react from "@vitejs/plugin-react";
import { build } from "vite";

const UI = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outArg = process.argv.indexOf("--out");
const OUT = outArg > 0 ? resolve(process.argv[outArg + 1]) : resolve(UI, "public/verify.html");
const PIN =
  process.env.ESIGN_PINNED_TSA_ROOT ??
  resolve(UI, "../api/app/assets/digicert_trusted_root_g4.pem");

const pem = readFileSync(PIN, "utf8");
if (!pem.includes("-----BEGIN CERTIFICATE-----")) throw new Error(`no certificate in ${PIN}`);

const result = await build({
  configFile: false,
  root: UI,
  logLevel: "warn",
  plugins: [react()],
  resolve: { alias: { "@": UI } },
  define: {
    "process.env.NODE_ENV": JSON.stringify("production"),
    __PINNED_TSA_ROOT_PEM__: JSON.stringify(pem),
  },
  build: {
    write: false,
    minify: true,
    emptyOutDir: false,
    lib: {
      entry: resolve(UI, "verifier/entry.tsx"),
      formats: ["iife"],
      name: "EsignVerifier",
      fileName: () => "verifier.js",
    },
  },
});
const outputs = (Array.isArray(result) ? result : [result]).flatMap((r) => r.output);
const chunk = outputs.find((o) => o.type === "chunk");
if (!chunk) throw new Error("vite produced no JS chunk");
const script = chunk.code.trim();

const tailwindConfig = (await import(resolve(UI, "tailwind.config.js"))).default;
const css = await postcss([
  tailwindcss({
    ...tailwindConfig,
    content: [resolve(UI, "components/verify/**/*.tsx"), resolve(UI, "verifier/**/*.{tsx,html}")],
  }),
  autoprefixer(),
]).process(readFileSync(resolve(UI, "app/globals.css"), "utf8"), { from: undefined });
const style = css.css.trim();

// Inline <script>/<style> content must not be able to close its own element early.
for (const [label, body, closer] of [
  ["script", script, /<\/script/i],
  ["style", style, /<\/style/i],
]) {
  if (closer.test(body) || body.includes("<!--")) {
    throw new Error(`inline ${label} contains a sequence that would break out of the element`);
  }
}

const hash = (s) => `'sha256-${createHash("sha256").update(s, "utf8").digest("base64")}'`;
const csp = [
  "default-src 'none'",
  `script-src ${hash(script)}`,
  `style-src ${hash(style)}`,
  "img-src data:",
  "connect-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join("; ");

const html = readFileSync(resolve(UI, "verifier/template.html"), "utf8")
  .replace("%%CSP%%", csp)
  .replace("%%STYLE%%", () => style)
  .replace("%%SCRIPT%%", () => script);

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, html);
const digest = createHash("sha256").update(html).digest("hex");
console.log(`built ${OUT} (${(html.length / 1024).toFixed(0)} KiB, sha256 ${digest})`);
