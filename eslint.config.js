import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/.wrangler/**",
      "**/.tmp/**",
      ".delivery-control/**",
      ".preview-source/**",
      "preview-artifact/**",
      "pnpm-lock.yaml",
      "apps/worker/worker-configuration.d.ts",
      "apps/marketing/worker-configuration.d.ts"
    ]
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: {
      globals: {
        Buffer: "readonly",
        fetch: "readonly",
        process: "readonly",
        setTimeout: "readonly"
      }
    }
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    ...tseslint.configs.disableTypeChecked,
    files: ["scripts/delivery/**/*.mjs", "scripts/local/**/*.mjs", "scripts/publication/**/*.mjs"]
  },
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ["packages/db/drizzle.config.ts"]
        },
        tsconfigRootDir: import.meta.dirname
      }
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error"
    }
  },
  prettier
);
