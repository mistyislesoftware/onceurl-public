import { runPnpm, runProcess } from "../database/helpers.mjs";

const commands = [
  ["install", "--frozen-lockfile"],
  ["exec", "playwright", "install", "chromium"],
  ["audit:dependencies"],
  ["format"],
  ["repository-policy:check"],
  ["cf:types:check"],
  ["wrangler:validate"],
  ["db:migrations:check"],
  ["db:test:migrations"],
  ["typecheck"],
  ["lint"],
  ["test"],
  ["openapi:validate"],
  ["test:integration"],
  ["test:browser"],
  ["build"]
];

for (const argumentsList of commands) {
  runPnpm(argumentsList);
}

runProcess("git", ["diff", "--check"]);
process.stdout.write("Complete repository validation passed.\n");
