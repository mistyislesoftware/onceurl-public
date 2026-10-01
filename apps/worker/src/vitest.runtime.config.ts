import { fileURLToPath, URL as NodeUrl } from "node:url";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const migrations = await readD1Migrations(
  fileURLToPath(new NodeUrl("../../../packages/db/drizzle/migrations", import.meta.url))
);

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: {
        configPath: fileURLToPath(new NodeUrl("../wrangler.jsonc", import.meta.url))
      },
      miniflare: {
        bindings: { TEST_D1_MIGRATIONS: migrations }
      }
    })
  ],
  test: {
    include: ["apps/worker/src/**/*.runtime.test.ts"]
  }
});
