CREATE TABLE `phase1a_metric_aggregates` (
	`time_bucket` integer NOT NULL,
	`dimensions` text NOT NULL,
	`count` integer NOT NULL,
	`processed_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	PRIMARY KEY(`time_bucket`, `dimensions`),
	CONSTRAINT "phase1a_metric_aggregates_dimensions" CHECK(json_valid("phase1a_metric_aggregates"."dimensions") AND json_type("phase1a_metric_aggregates"."dimensions") = 'object'),
	CONSTRAINT "phase1a_metric_aggregates_window" CHECK("phase1a_metric_aggregates"."time_bucket" >= 0 AND "phase1a_metric_aggregates"."time_bucket" % 3600000 = 0 AND "phase1a_metric_aggregates"."retain_until" = "phase1a_metric_aggregates"."time_bucket" + 15552000000),
	CONSTRAINT "phase1a_metric_aggregates_count" CHECK(typeof("phase1a_metric_aggregates"."count") = 'integer' AND "phase1a_metric_aggregates"."count" > 0)
);
--> statement-breakpoint
CREATE INDEX `phase1a_metric_aggregates_retention_idx` ON `phase1a_metric_aggregates` (`retain_until`);--> statement-breakpoint
CREATE TABLE `phase1a_metric_receipts` (
	`event_id` text PRIMARY KEY NOT NULL,
	`time_bucket` integer NOT NULL,
	`dimensions` text NOT NULL,
	`processed_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	`applied` integer DEFAULT 0 NOT NULL,
	CONSTRAINT "phase1a_metric_receipts_dimensions" CHECK(json_valid("phase1a_metric_receipts"."dimensions") AND json_type("phase1a_metric_receipts"."dimensions") = 'object'),
	CONSTRAINT "phase1a_metric_receipts_window" CHECK("phase1a_metric_receipts"."time_bucket" >= 0 AND "phase1a_metric_receipts"."time_bucket" % 3600000 = 0 AND "phase1a_metric_receipts"."retain_until" = "phase1a_metric_receipts"."time_bucket" + 2592000000),
	CONSTRAINT "phase1a_metric_receipts_applied" CHECK("phase1a_metric_receipts"."applied" IN (0, 1))
);
--> statement-breakpoint
CREATE INDEX `phase1a_metric_receipts_retention_idx` ON `phase1a_metric_receipts` (`retain_until`);--> statement-breakpoint
CREATE TABLE `phase1a_metrics_clock` (
	`id` integer PRIMARY KEY NOT NULL,
	`processed_at` integer NOT NULL,
	CONSTRAINT "phase1a_metrics_clock_singleton" CHECK("phase1a_metrics_clock"."id" = 1 AND "phase1a_metrics_clock"."processed_at" >= 0)
);
