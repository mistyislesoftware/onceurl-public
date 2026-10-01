CREATE TABLE `capabilities` (
	`id` text PRIMARY KEY NOT NULL,
	`workspace_id` text,
	`created_by_user_id` text,
	`kind` text NOT NULL,
	`state` text NOT NULL,
	`public_token_hash` text NOT NULL,
	`owner_token_hash` text,
	`public_alias` text,
	`policy_json` text NOT NULL,
	`expires_at` integer,
	`consumed_at` integer,
	`disabled_at` integer,
	`deleted_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`version` integer DEFAULT 1 NOT NULL,
	CONSTRAINT "capabilities_public_token_hash_non_empty" CHECK(length("capabilities"."public_token_hash") > 0),
	CONSTRAINT "capabilities_owner_token_hash_non_empty" CHECK("capabilities"."owner_token_hash" is null or length("capabilities"."owner_token_hash") > 0),
	CONSTRAINT "capabilities_policy_json_object" CHECK(json_valid("capabilities"."policy_json") = 1 and case when json_valid("capabilities"."policy_json") = 1 then json_type("capabilities"."policy_json") = 'object' else 0 end),
	CONSTRAINT "capabilities_version_positive_integer" CHECK(typeof("capabilities"."version") = 'integer' and "capabilities"."version" > 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `capabilities_public_token_hash_unique` ON `capabilities` (`public_token_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `capabilities_owner_token_hash_unique` ON `capabilities` (`owner_token_hash`) WHERE "capabilities"."owner_token_hash" is not null;--> statement-breakpoint
CREATE INDEX `capabilities_state_expires_at_idx` ON `capabilities` (`state`,`expires_at`);--> statement-breakpoint
CREATE INDEX `capabilities_workspace_id_created_at_idx` ON `capabilities` (`workspace_id`,`created_at`);--> statement-breakpoint
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
);
