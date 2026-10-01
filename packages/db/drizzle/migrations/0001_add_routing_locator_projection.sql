ALTER TABLE `capabilities` ADD `routing_locator` text;--> statement-breakpoint
UPDATE `capabilities`
SET `routing_locator` = 'loc1_' || lower(hex(randomblob(24)))
WHERE `routing_locator` IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX `capabilities_routing_locator_unique` ON `capabilities` (`routing_locator`);--> statement-breakpoint
CREATE TABLE `__old_capability_counters` (
	`capability_id` text PRIMARY KEY NOT NULL,
	`view_count` integer NOT NULL,
	`consumption_count` integer NOT NULL,
	`download_count` integer NOT NULL,
	`upload_count` integer NOT NULL,
	`click_count` integer NOT NULL,
	`updated_at` integer NOT NULL
);--> statement-breakpoint
INSERT INTO `__old_capability_counters`("capability_id", "view_count", "consumption_count", "download_count", "upload_count", "click_count", "updated_at") SELECT "capability_id", "view_count", "consumption_count", "download_count", "upload_count", "click_count", "updated_at" FROM `capability_counters`;--> statement-breakpoint
DROP TABLE `capability_counters`;--> statement-breakpoint
CREATE TABLE `__new_capabilities` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text,
	`created_by_user_id` text,
	`kind` text NOT NULL,
	`state` text NOT NULL,
	`routing_locator` text NOT NULL,
	`public_alias` text,
	`policy_json` text NOT NULL,
	`expires_at` integer,
	`consumed_at` integer,
	`disabled_at` integer,
	`deleted_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	CONSTRAINT "capabilities_routing_locator_format" CHECK(length("__new_capabilities"."routing_locator") = 53 and substr("__new_capabilities"."routing_locator", 1, 5) = 'loc1_' and substr("__new_capabilities"."routing_locator", 6) not glob '*[^0-9a-f]*'),
	CONSTRAINT "capabilities_policy_json_object" CHECK(json_valid("__new_capabilities"."policy_json") = 1 and case when json_valid("__new_capabilities"."policy_json") = 1 then json_type("__new_capabilities"."policy_json") = 'object' else 0 end),
	CONSTRAINT "capabilities_version_positive_integer" CHECK(typeof("__new_capabilities"."version") = 'integer' and "__new_capabilities"."version" > 0)
);
--> statement-breakpoint
INSERT INTO `__new_capabilities`("id", "workspace_id", "created_by_user_id", "kind", "state", "routing_locator", "public_alias", "policy_json", "expires_at", "consumed_at", "disabled_at", "deleted_at", "created_at", "updated_at", "version") SELECT "id", "workspace_id", "created_by_user_id", "kind", "state", "routing_locator", "public_alias", "policy_json", "expires_at", "consumed_at", "disabled_at", "deleted_at", "created_at", "updated_at", "version" FROM `capabilities`;--> statement-breakpoint
DROP TABLE `capabilities`;--> statement-breakpoint
ALTER TABLE `__new_capabilities` RENAME TO `capabilities`;--> statement-breakpoint
CREATE TABLE `capability_counters` (
	`capability_id` text PRIMARY KEY NOT NULL,
	`view_count` integer DEFAULT 0 NOT NULL,
	`consumption_count` integer DEFAULT 0 NOT NULL,
	`download_count` integer DEFAULT 0 NOT NULL,
	`upload_count` integer DEFAULT 0 NOT NULL,
	`click_count` integer DEFAULT 0 NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`capability_id`) REFERENCES `capabilities`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "capability_counters_view_count_non_negative" CHECK(typeof("capability_counters"."view_count") = 'integer' and "capability_counters"."view_count" >= 0),
	CONSTRAINT "capability_counters_consumption_count_non_negative" CHECK(typeof("capability_counters"."consumption_count") = 'integer' and "capability_counters"."consumption_count" >= 0),
	CONSTRAINT "capability_counters_download_count_non_negative" CHECK(typeof("capability_counters"."download_count") = 'integer' and "capability_counters"."download_count" >= 0),
	CONSTRAINT "capability_counters_upload_count_non_negative" CHECK(typeof("capability_counters"."upload_count") = 'integer' and "capability_counters"."upload_count" >= 0),
	CONSTRAINT "capability_counters_click_count_non_negative" CHECK(typeof("capability_counters"."click_count") = 'integer' and "capability_counters"."click_count" >= 0)
);--> statement-breakpoint
INSERT INTO `capability_counters`("capability_id", "view_count", "consumption_count", "download_count", "upload_count", "click_count", "updated_at") SELECT "capability_id", "view_count", "consumption_count", "download_count", "upload_count", "click_count", "updated_at" FROM `__old_capability_counters`;--> statement-breakpoint
DROP TABLE `__old_capability_counters`;--> statement-breakpoint
CREATE UNIQUE INDEX `capabilities_routing_locator_unique` ON `capabilities` (`routing_locator`);--> statement-breakpoint
CREATE INDEX `capabilities_state_expires_at_idx` ON `capabilities` (`state`,`expires_at`);--> statement-breakpoint
CREATE INDEX `capabilities_workspace_id_created_at_idx` ON `capabilities` (`workspace_id`,`created_at`);
