CREATE TABLE `capability_projection_events` (
	`capability_id` text NOT NULL,
	`event_id` text NOT NULL,
	`event_type` text NOT NULL,
	`projection_version` integer NOT NULL,
	`occurred_at` integer NOT NULL,
	`processed_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	PRIMARY KEY(`capability_id`, `event_id`),
	CONSTRAINT "capability_projection_events_version_positive" CHECK(typeof("capability_projection_events"."projection_version") = 'integer' and "capability_projection_events"."projection_version" > 0),
	CONSTRAINT "capability_projection_events_retention_order" CHECK("capability_projection_events"."retain_until" >= "capability_projection_events"."occurred_at")
);
--> statement-breakpoint
CREATE INDEX `capability_projection_events_retention_idx` ON `capability_projection_events` (`retain_until`);--> statement-breakpoint
CREATE TABLE `capability_reconciliation_candidates` (
	`capability_id` text PRIMARY KEY NOT NULL,
	`routing_locator` text NOT NULL,
	`reason` text NOT NULL,
	`next_attempt_at` integer NOT NULL,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`last_attempt_at` integer,
	`created_at` integer NOT NULL,
	`retain_until` integer,
	CONSTRAINT "capability_reconciliation_candidates_attempts_non_negative" CHECK(typeof("capability_reconciliation_candidates"."attempt_count") = 'integer' and "capability_reconciliation_candidates"."attempt_count" >= 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `capability_reconciliation_candidates_locator_unique` ON `capability_reconciliation_candidates` (`routing_locator`);--> statement-breakpoint
CREATE INDEX `capability_reconciliation_candidates_due_idx` ON `capability_reconciliation_candidates` (`next_attempt_at`,`capability_id`);--> statement-breakpoint
CREATE INDEX `capability_reconciliation_candidates_retention_idx` ON `capability_reconciliation_candidates` (`retain_until`);--> statement-breakpoint
CREATE TABLE `capability_terminal_tombstones` (
	`capability_id` text PRIMARY KEY NOT NULL,
	`routing_locator` text NOT NULL,
	`terminal_state` text NOT NULL,
	`projection_version` integer NOT NULL,
	`terminal_event_id` text NOT NULL,
	`terminal_at` integer NOT NULL,
	`catalogue_delete_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	`last_verified_at` integer,
	CONSTRAINT "capability_terminal_tombstones_state" CHECK("capability_terminal_tombstones"."terminal_state" in ('CONSUMED', 'EXPIRED', 'DELETED')),
	CONSTRAINT "capability_terminal_tombstones_version_positive" CHECK(typeof("capability_terminal_tombstones"."projection_version") = 'integer' and "capability_terminal_tombstones"."projection_version" > 0),
	CONSTRAINT "capability_terminal_tombstones_retention_order" CHECK("capability_terminal_tombstones"."retain_until" >= "capability_terminal_tombstones"."terminal_at" and "capability_terminal_tombstones"."catalogue_delete_at" <= "capability_terminal_tombstones"."retain_until")
);
--> statement-breakpoint
CREATE UNIQUE INDEX `capability_terminal_tombstones_locator_unique` ON `capability_terminal_tombstones` (`routing_locator`);--> statement-breakpoint
CREATE INDEX `capability_terminal_tombstones_catalogue_cleanup_idx` ON `capability_terminal_tombstones` (`catalogue_delete_at`);--> statement-breakpoint
CREATE INDEX `capability_terminal_tombstones_retention_idx` ON `capability_terminal_tombstones` (`retain_until`);