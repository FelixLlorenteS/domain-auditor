import { defineConfig } from "vitest/config";

// Live validation against real domains: slow and needs network, so it is kept
// out of `pnpm test` and run on demand with `pnpm validate`.
export default defineConfig({
  test: { environment: "node", include: ["validation/validate.test.ts"], testTimeout: 180_000, hookTimeout: 180_000, fileParallelism: false },
});
