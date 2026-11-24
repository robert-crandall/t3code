CREATE TABLE "relay_oauth_sessions" (
	"id" varchar(64) PRIMARY KEY,
	"current_token_hash" varchar(128) NOT NULL,
	"previous_token_hash" varchar(128),
	"auth_code_jti" varchar(128),
	"auth_code_expires_at" varchar(64),
	"user_id" varchar(191) NOT NULL,
	"github_login" varchar(191) NOT NULL,
	"email" text,
	"client_id" varchar(64) NOT NULL,
	"rotated_at" varchar(64),
	"revoked_at" varchar(64),
	"expires_at" varchar(64) NOT NULL,
	"absolute_expires_at" varchar(64) NOT NULL,
	"created_at" varchar(64) NOT NULL,
	"updated_at" varchar(64) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_relay_oauth_sessions_current_token_hash" ON "relay_oauth_sessions" ("current_token_hash");
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_relay_oauth_sessions_previous_token_hash" ON "relay_oauth_sessions" ("previous_token_hash");
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_relay_oauth_sessions_auth_code_jti" ON "relay_oauth_sessions" ("auth_code_jti");
--> statement-breakpoint
CREATE INDEX "idx_relay_oauth_sessions_expires_at" ON "relay_oauth_sessions" ("expires_at");
