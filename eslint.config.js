import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules", "release"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  // Electron loads sandboxed preload scripts as CommonJS only.
  { files: ["desktop/*.cjs"], rules: { "@typescript-eslint/no-require-imports": "off" } },
);
