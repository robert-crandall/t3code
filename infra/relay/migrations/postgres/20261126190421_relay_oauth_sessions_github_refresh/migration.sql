ALTER TABLE "relay_oauth_sessions" ADD COLUMN "encrypted_github_refresh_token" text;--> statement-breakpoint
ALTER TABLE "relay_oauth_sessions" ADD COLUMN "github_refresh_lease_until" varchar(64);