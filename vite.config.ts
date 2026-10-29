import { defineConfig } from "vite-plus";

const sourceOnly = ["**", "!/src", "!/src/**", "!/test", "!/test/**"];

export default defineConfig({
  pack: {
    entry: ["src/cli.ts"],
    format: ["esm"],
    dts: true,
    clean: true,
    // Node defaults to .mjs. The package is "type": "module" and the bin is dist/cli.js.
    fixedExtension: false,
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 10_000,
  },
  fmt: {
    ignorePatterns: sourceOnly,
  },
  lint: {
    ignorePatterns: sourceOnly,
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: { "vite-plus/prefer-vite-plus-imports": "error" },
    options: { typeAware: true, typeCheck: true },
  },
});
