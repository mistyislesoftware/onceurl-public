import { defineConfig } from "drizzle-kit";

export default defineConfig({
  breakpoints: true,
  dialect: "sqlite",
  out: "./drizzle/migrations",
  schema: "./src/schema.ts"
});
