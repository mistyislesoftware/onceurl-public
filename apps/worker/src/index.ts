import { app } from "./app";
import { handleCapabilityQueue, handleCapabilityReconciliation } from "./capability-delivery";
import type { WorkerEnv } from "./env";
import { cleanupAbuseRetention } from "./abuse-records";
import { cleanupMetrics } from "./phase1a-metrics";

export { CapabilityDurableObject } from "./capability-durable-object";
export { AbuseControlDurableObject } from "./abuse-control-durable-object";

export default {
  fetch: app.fetch,
  queue: handleCapabilityQueue,
  async scheduled(controller, env): Promise<void> {
    if (env.DB !== undefined) {
      try {
        const cleanup = await cleanupMetrics(env.DB, controller.scheduledTime);
        if (!cleanup.complete)
          console.warn("metrics_retention_backlog", { category: "budget_exhausted" });
      } catch {
        console.error("metrics_retention_cleanup_failed", { category: "d1" });
      }
      try {
        await cleanupAbuseRetention(env.DB, controller.scheduledTime);
      } catch {
        console.error("abuse_retention_cleanup_failed", { category: "d1" });
      }
    }
    await handleCapabilityReconciliation(env, controller.scheduledTime);
  }
} satisfies ExportedHandler<WorkerEnv>;

export { StagingReliabilityWorkflow } from "./staging-reliability-workflow";
