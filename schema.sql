-- ============================================================
-- CARVE — entitlement service schema (Cloudflare D1 / SQLite)
-- KG Studio
-- ------------------------------------------------------------
-- Four tables, and deliberately no more. The product decision was "the
-- minimum that makes entitlement work": Google sub, email, entitlement
-- records, Stripe customer id. Progress sync and analytics are separate
-- features with separate consent and are NOT at launch.
--
-- Adding a column here is a privacy-policy change, not a schema change.
-- Every field is something we must name in the policy, justify keeping, and
-- hand back or delete on request. Push back before adding one.
-- ============================================================

PRAGMA foreign_keys = ON;


-- ------------------------------------------------------------
-- One row per Google identity.
--
-- Keyed on `sub`, not email. Google's `sub` is stable for the life of the
-- account; an email address can be changed by the user and, on Workspace
-- domains, reassigned to a different person entirely. Keying on email would
-- eventually hand one person another person's purchases.
--
-- `email` is stored anyway because a buyer with a payment problem writes in
-- from their email address and support has to find them. It is contact data,
-- not identity.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  google_sub          TEXT    NOT NULL UNIQUE,
  email               TEXT    NOT NULL,
  stripe_customer_id  TEXT    UNIQUE,
  created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


-- ------------------------------------------------------------
-- What a user owns.
--
-- `revoked_at` rather than DELETE: a refund or chargeback has to be
-- auditable. If a buyer disputes, "when did we grant it and when did we take
-- it back" is the question, and a deleted row cannot answer it.
--
-- `stripe_session_id` is UNIQUE because that is the idempotency key. Stripe
-- delivers webhooks AT LEAST once and retries on any non-2xx, so the same
-- checkout can arrive several times; the constraint makes a double-grant
-- impossible at the database rather than relying on handler logic.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entitlements (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sku                TEXT    NOT NULL,
  source             TEXT    NOT NULL CHECK (source IN ('stripe', 'grant')),
  stripe_session_id  TEXT    UNIQUE,
  granted_at         TEXT    NOT NULL DEFAULT (datetime('now')),
  revoked_at         TEXT
);

-- One ACTIVE entitlement per user per sku. Partial index, so a revoked row
-- does not block re-purchase after a refund.
CREATE UNIQUE INDEX IF NOT EXISTS idx_entitlements_active
  ON entitlements(user_id, sku) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_entitlements_user ON entitlements(user_id);


-- ------------------------------------------------------------
-- Sign-in sessions.
--
-- `id` holds a SHA-256 hash of the session token, never the token itself.
-- The raw token lives only in the user's cookie. If this table ever leaks,
-- the hashes cannot be replayed as sessions — which is the entire reason to
-- pay the hashing cost on a table this small.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id          TEXT    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);


-- ------------------------------------------------------------
-- Webhook idempotency.
--
-- Separate from the entitlements constraint on purpose: that one stops a
-- duplicate GRANT, this one stops a duplicate of any event we handle,
-- including refunds and future event types that have no natural unique key.
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS processed_events (
  event_id      TEXT PRIMARY KEY,
  type          TEXT NOT NULL,
  processed_at  TEXT NOT NULL DEFAULT (datetime('now'))
);


-- ------------------------------------------------------------
-- Account deletion (GDPR Art. 17 / CCPA) is one statement:
--
--     DELETE FROM users WHERE google_sub = ?;
--
-- ON DELETE CASCADE clears sessions and entitlements with it. That is why
-- the foreign keys are declared rather than left implicit — "delete my
-- account" has to actually delete, and a cascade is much harder to get
-- wrong than three statements in the right order.
--
-- processed_events deliberately does NOT cascade: it holds Stripe event ids,
-- not personal data, and clearing it would let an old webhook retry re-grant
-- an entitlement to a user who asked to be forgotten.
-- ------------------------------------------------------------
