import { defineConfig } from "vitest/config";

// Comparison with internet.nl (`pnpm validate:nl`): each test there takes one to
// three minutes, so it runs apart from `pnpm validate`, one domain at a time.
export default defineConfig({
  test: { environment: "node", include: ["validation/internetnl.test.ts"], testTimeout: 600_000, hookTimeout: 600_000, fileParallelism: false },
});
