CREATE TABLE `abuse_reports` (
	`id` text PRIMARY KEY NOT NULL,
	`routing_locator` text NOT NULL,
	`reason` text NOT NULL,
	`note` text,
	`created_at` integer NOT NULL,
	`note_delete_at` integer NOT NULL,
	`confirmed_at` integer,
	`retain_until` integer NOT NULL,
	`version` integer NOT NULL,
	CONSTRAINT "abuse_reports_note_bytes" CHECK("abuse_reports"."note" is null or length(cast("abuse_reports"."note" as blob)) <= 1024),
	CONSTRAINT "abuse_reports_reason" CHECK("abuse_reports"."reason" in ('phishing','malware','harassment','spam','other')),
	CONSTRAINT "abuse_reports_retention" CHECK("abuse_reports"."note_delete_at" = "abuse_reports"."created_at" + 2592000000 and (("abuse_reports"."confirmed_at" is null and "abuse_reports"."retain_until" = "abuse_reports"."created_at" + 2592000000) or ("abuse_reports"."confirmed_at" >= "abuse_reports"."created_at" and "abuse_reports"."retain_until" = "abuse_reports"."confirmed_at" + 15552000000))),
	CONSTRAINT "abuse_reports_version" CHECK(typeof("abuse_reports"."version") = 'integer' and "abuse_reports"."version" > 0)
);
--> statement-breakpoint
CREATE INDEX `abuse_reports_retention_idx` ON `abuse_reports` (`retain_until`);--> statement-breakpoint
CREATE INDEX `abuse_reports_note_cleanup_idx` ON `abuse_reports` (`note_delete_at`);--> statement-breakpoint
CREATE INDEX `abuse_reports_created_idx` ON `abuse_reports` (`created_at`,`id`);--> statement-breakpoint
CREATE TABLE `admin_audit` (
	`id` text PRIMARY KEY NOT NULL,
	`routing_locator` text NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`reason` text NOT NULL,
	`report_id` text,
	`occurred_at` integer NOT NULL,
	`retain_until` integer NOT NULL,
	CONSTRAINT "admin_audit_action" CHECK("admin_audit"."action" in ('disable','abuse_lock','delete','release')),
	CONSTRAINT "admin_audit_reason" CHECK("admin_audit"."reason" in ('phishing','malware','harassment','spam','other')),
	CONSTRAINT "admin_audit_retention" CHECK("admin_audit"."retain_until" = "admin_audit"."occurred_at" + 15552000000)
);
--> statement-breakpoint
CREATE INDEX `admin_audit_retention_idx` ON `admin_audit` (`retain_until`);