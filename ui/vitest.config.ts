import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The browser evidence verifier embeds the api's pinned TSA root at build time (see
// lib/verify/pinnedRoot.ts and scripts/build-verifier.mjs); tests get the same file.
const PINNED_TSA_ROOT = resolve(__dirname, "../api/app/assets/digicert_trusted_root_g4.pem");

export default defineConfig({
  plugins: [react()],
  define: {
    __PINNED_TSA_ROOT_PEM__: JSON.stringify(readFileSync(PINNED_TSA_ROOT, "utf8")),
  },
  resolve: { tsconfigPaths: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    globals: true,
    css: false,
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary"],
      include: ["app/**/*.{ts,tsx}", "components/**/*.{ts,tsx}", "lib/**/*.{ts,tsx}"],
      exclude: ["**/*.d.ts", "**/*.config.*", "**/.next/**"],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
