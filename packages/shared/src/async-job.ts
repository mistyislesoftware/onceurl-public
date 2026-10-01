export interface AsyncJobEnvelope {
  event_id: string;
  idempotency_key: string;
  attempt: number;
  resource_id: string;
  operation: string;
  /** ISO-8601 UTC timestamp for when the job was created. */
  created_at: string;
}
