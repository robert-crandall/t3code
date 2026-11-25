ALTER TABLE "relay_oauth_sessions" ADD COLUMN "previous_token_hash" varchar(128);--> statement-breakpoint
ALTER TABLE "relay_oauth_sessions" ADD COLUMN "encrypted_current_refresh_token" text;