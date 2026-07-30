-- ============================================================
-- CARVE — entitlement service schema (MySQL 8 / Percona)
-- KG Studio
-- ------------------------------------------------------------
-- Ported from schema.sql (SQLite/D1) when the service consolidated onto the
-- Bluehost box. Same four tables, same guarantees — but two of them could not
-- be expressed the same way, and those are the parts worth reading.
--
-- Four tables, deliberately no more. The product decision was "the minimum
-- that makes entitlement work": Google sub, email, entitlement records,
-- Stripe customer id. Progress sync and analytics are separate features with
-- separate consent and are NOT at launch.
--
-- Adding a column here is a privacy-policy change, not a schema change.
-- ============================================================

-- utf8mb4 throughout: emails and Google display data are arbitrary Unicode,
-- and MySQL's old `utf8` is a three-byte subset that mangles anything past
-- the BMP. Collation is explicit rather than server-default so a host
-- migration cannot silently change comparison behaviour.
SET NAMES utf8mb4;


-- ------------------------------------------------------------
-- One row per Google identity.
--
-- Keyed on `sub`, not email. Google's `sub` is stable for the life of the
-- account; an email can be changed by the user and, on Workspace domains,
-- reassigned to a different person. Keying on email would eventually hand
-- someone another person's purchases.
--
-- google_sub is VARCHAR(255) — Google documents `sub` as up to 255 chars, and
-- it is a string, never an integer, however numeric it looks today.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  google_sub          VARCHAR(255)    NOT NULL,
  email               VARCHAR(320)    NOT NULL,
  stripe_customer_id  VARCHAR(255)    DEFAULT NULL,
  created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                      ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uniq_users_google_sub (google_sub),
  UNIQUE KEY uniq_users_stripe_customer (stripe_customer_id),
  KEY idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- ------------------------------------------------------------
-- What a user owns.
--
-- THE PORT THAT MATTERS. SQLite enforced "one ACTIVE entitlement per user per
-- sku" with a partial index:
--
--     CREATE UNIQUE INDEX ... ON entitlements(user_id, sku)
--       WHERE revoked_at IS NULL;
--
-- MySQL has no partial indexes, so that constraint would have been silently
-- lost in translation — and it is load-bearing on the payment path. It stops
-- a double grant while still allowing a re-purchase after a refund.
--
-- The equivalent here is a generated column that holds `user_id:sku` while
-- the row is active and NULL once it is revoked, with a UNIQUE index over it.
-- MySQL unique indexes permit unlimited NULLs, so revoked rows stop competing
-- the moment they are revoked. Same guarantee, different mechanism.
--
-- STORED rather than VIRTUAL because MySQL cannot index a virtual column in
-- all versions and a stored one is unambiguous.
--
-- `revoked_at` rather than DELETE: a refund or chargeback has to be
-- auditable. "When did we grant it and when did we take it back" is
-- unanswerable from a deleted row.
--
-- stripe_session_id is UNIQUE because that is the idempotency key. Stripe
-- delivers webhooks AT LEAST once and retries on any non-2xx, so the same
-- checkout can arrive repeatedly; the constraint makes a double-grant
-- impossible at the database rather than trusting handler logic.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entitlements (
  id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id            BIGINT UNSIGNED NOT NULL,
  sku                VARCHAR(64)     NOT NULL,
  source             ENUM('stripe','grant') NOT NULL,
  stripe_session_id  VARCHAR(255)    DEFAULT NULL,
  granted_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at         DATETIME        DEFAULT NULL,

  active_key VARCHAR(320)
    GENERATED ALWAYS AS (
      IF(revoked_at IS NULL, CONCAT(user_id, ':', sku), NULL)
    ) STORED,

  PRIMARY KEY (id),
  UNIQUE KEY uniq_entitlements_session (stripe_session_id),
  UNIQUE KEY uniq_entitlements_active (active_key),
  KEY idx_entitlements_user (user_id),
  CONSTRAINT fk_entitlements_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- ------------------------------------------------------------
-- Sign-in sessions.
--
-- `id` holds a SHA-256 hash of the session token, never the token. The raw
-- token lives only in the user's cookie, so a database leak cannot be
-- replayed as live sessions.
--
-- CHAR(64) not VARCHAR: a hex SHA-256 is always exactly 64 characters, and a
-- fixed-width primary key indexes better.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id          CHAR(64)        NOT NULL,
  user_id     BIGINT UNSIGNED NOT NULL,
  created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  DATETIME        NOT NULL,
  PRIMARY KEY (id),
  KEY idx_sessions_user (user_id),
  KEY idx_sessions_expires (expires_at),
  CONSTRAINT fk_sessions_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- ------------------------------------------------------------
-- Webhook idempotency.
--
-- Separate from the entitlements constraint on purpose: that one stops a
-- duplicate GRANT, this one stops a duplicate of any event we handle,
-- including refunds and future event types with no natural unique key.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS processed_events (
  event_id      VARCHAR(255) NOT NULL,
  type          VARCHAR(128) NOT NULL,
  processed_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;


-- ------------------------------------------------------------
-- SECOND THING THAT DID NOT PORT: `ON DELETE CASCADE` is declared above, but
-- InnoDB enforces foreign keys always — there is no `PRAGMA foreign_keys` to
-- forget, unlike SQLite where the pragma is per-connection and OFF by
-- default. So account deletion is still one statement:
--
--     DELETE FROM users WHERE google_sub = ?;
--
-- and it genuinely cascades to sessions and entitlements. GDPR Art. 17 /
-- CCPA: "delete my account" has to actually delete, and a cascade is much
-- harder to get wrong than three statements in the right order.
--
-- processed_events deliberately does NOT cascade — it holds Stripe event ids,
-- not personal data, and clearing it would let an old webhook retry re-grant
-- an entitlement to a user who asked to be forgotten.
-- ------------------------------------------------------------
