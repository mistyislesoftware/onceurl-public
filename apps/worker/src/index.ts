import { app } from "./app";
import { handleCapabilityQueue, handleCapabilityReconciliation } from "./capability-delivery";
import type { WorkerEnv } from "./env";

export { CapabilityDurableObject } from "./capability-durable-object";
export { AbuseControlDurableObject } from "./abuse-control-durable-object";

export default {
  fetch: app.fetch,
  queue: handleCapabilityQueue,
  async scheduled(controller, env): Promise<void> {
    await handleCapabilityReconciliation(env, controller.scheduledTime);
  }
} satisfies ExportedHandler<WorkerEnv>;
