import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  css: {
    postcss: {
      plugins: [],
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
    testTimeout: 10_000,
  },
});
