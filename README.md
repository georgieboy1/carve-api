# carve-api

> **Running on Bluehost, not Cloudflare.** The Workers/D1 version is still in
> the git history and in `src/*.js` / `wrangler.jsonc` as reference. What runs
> is PHP 8.4 + MySQL 8 at `https://api.futureoftheisles.org`.

## How deploys work

Push to `main`. The server pulls it within two minutes.

```
cron (*/2) → tools/deploy.sh → git fetch → lint → reset --hard → check /health
```

There is no build step and nothing pushes to the server. It pulls, because
shared hosting has no deploy hooks. Consequences worth knowing:

- **What runs always corresponds to a commit.** `GET /health` reports it, so
  "is the fix live yet" needs no shell access.
- **A syntax error will not deploy.** The script stages the new tree, runs
  `php -l` over it, and refuses rather than swapping in a front controller
  that would take down every route — including the Stripe webhook, which
  Stripe then retries for days.
- **The checkout is a deploy target, not a workspace.** `reset --hard` means
  hand edits on the server are destroyed on the next pull. That is the point:
  a server quietly diverging from the repo is worse than losing an edit.
- Log: `/home1/fxxfjgmy/logs/carve-deploy.log`. Only real deploys and
  refusals are logged — a fetch failure exits quietly so an outage does not
  bury the errors that matter.

Rollback is `git revert` and a two-minute wait.

Entitlement service for [Carve](https://carve.futureoftheisles.org). Google
sign-in, Stripe purchases, and the one question the game cannot answer for
itself: **is this signed-in person allowed to play the paid collections?**

Cloudflare Workers + D1. Separate repo from the game on purpose — the game is
public and served by GitHub Pages, and the revenue path wants its own deploy
pipeline and its own history.

## Why this exists

Carve previously sealed the paid levels behind a single shared passphrase
(`sealed.js` / `unlock.js` in the game repo). That stopped casual bypass but
could never stop a buyer redistributing the key, because the key has to reach
their machine to work. Entitlement checked on a server they do not control
closes that hole.

The trade is offline play, which is a shipped and advertised feature. So the
client caches a successful entitlement check with an expiry: a signed-in owner
can play on a plane, and the grace lapses if they never come back online.

## What is here

Steps 1–2: platform, schema, deploy pipeline, and Google sign-in.

| File | Role |
|---|---|
| `schema.sql` | Four tables. Adding a column is a privacy-policy change. |
| `src/index.js` | Entry and router. |
| `src/http.js` | CORS, JSON responses, session cookie, token hashing. |
| `src/auth.js` | Google OAuth (code + PKCE), sessions, signout. |
| `src/entitlement.js` | Entitlement read and the offline grace. |
| `wrangler.jsonc` | Worker config and the D1 binding. |
| `.github/workflows/deploy.yml` | Push to `main` → deploy → smoke test. |

| Route | Status |
|---|---|
| `GET /health` | done |
| `GET /auth/google` | done |
| `GET /auth/callback` | done |
| `POST /auth/signout` | done |
| `GET /entitlement` | done |
| `POST /checkout` | step 3 |
| `POST /webhook/stripe` | step 3 |
| `POST /account/delete` | step 4 |

### Google Cloud setup, before sign-in can work

APIs & Services → Credentials → **OAuth 2.0 Client ID**, type *Web
application*. Then:

- **Authorised redirect URI**: `https://api.futureoftheisles.org/auth/callback`
  — must match `API_ORIGIN` in `wrangler.jsonc` byte for byte, including
  scheme and any trailing path. A mismatch is the single most common failure
  and Google's error message for it is unhelpful.
- Scopes stay `openid email profile`. Nothing broader — it triggers heavier
  verification and buys entitlement nothing.
- The consent screen needs a published **privacy policy URL**, which is one
  more reason the policy rewrite is not an afterthought.

Then `wrangler secret put GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`.

## Setup

```bash
npm install
npx wrangler login          # interactive, opens a browser
npm run db:create           # prints a database_id
```

Put that `database_id` into `wrangler.jsonc`, replacing
`PLACEHOLDER_RUN_DB_CREATE`, then:

```bash
npm run db:migrate          # applies schema.sql to the remote database
npm run deploy
curl https://<your-worker>/health
```

`/health` returns `200` only when D1 is bound **and** all four tables exist.
A reachable-but-unmigrated database reports `503` with `migrated: false`,
rather than passing and failing on the first real request.

### Local

```bash
cp .dev.vars.example .dev.vars     # fill in TEST keys
npm run db:migrate:local
npm run dev
```

### Secrets

Never in the repo. Production:

```bash
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put STRIPE_WEBHOOK_SECRET
```

Locally the same names go in `.dev.vars`, which is gitignored.

### CI

The workflow needs two things on the repo:

- secret `CLOUDFLARE_API_TOKEN` — an API token with *Edit Cloudflare Workers*
- variable `API_ORIGIN` — e.g. `https://api.futureoftheisles.org`, used by the
  post-deploy smoke test. Unset just skips the test with a warning.

Migrations are **not** run by CI. `schema.sql` is idempotent so it would be
safe today, but a pipeline that has always applied migrations silently is the
one that applies a destructive one silently too.

## Design notes worth keeping

**Identity is Google `sub`, not email.** `sub` is stable for the life of the
account; an email address can be changed by the user and, on Workspace
domains, reassigned to a different person. Keying on email would eventually
hand someone another person's purchases. Email is stored as *contact* data —
a buyer with a payment problem writes in from it and support has to find them.

**Session tokens are stored hashed.** The raw token lives only in the user's
cookie; the table holds its SHA-256. If the database leaks, the hashes cannot
be replayed as live sessions.

**The session cookie is host-only.** No `Domain` attribute, so it is scoped to
the API hostname. `Domain=.futureoftheisles.org` would send the session token
to the WordPress site on every request there — which has no business receiving
it and runs a plugin stack we do not control.

**Same site, different origin.** `carve.` and `api.` share a registrable
domain, so the cookie can stay `SameSite=Lax` rather than `SameSite=None`.
CORS is still required because the *origin* differs, and `Allow-Origin` is
echoed from an allowlist — never `*`, which browsers ignore when credentials
are involved and which would look permissive while breaking every
authenticated request.

**Idempotency is enforced in the database, twice.** Stripe delivers webhooks
at least once and retries on any non-2xx, so the same checkout can arrive
repeatedly. `entitlements.stripe_session_id` is `UNIQUE`, and a partial unique
index allows one *active* entitlement per user per sku — so a refund
(`revoked_at`) still permits re-purchase. Handler logic can be wrong; a
constraint cannot.

**Revoke, never delete, an entitlement.** A chargeback needs an audit trail.
"When did we grant it and when did we take it back" is unanswerable from a
deleted row.

**Account deletion is one statement.** `DELETE FROM users WHERE google_sub = ?`
cascades to sessions and entitlements. `processed_events` deliberately does
not cascade — it holds Stripe event ids, not personal data, and clearing it
would let an old webhook retry re-grant an entitlement to someone who asked
to be forgotten.

## Not done, and blocking launch

- **A Google-certified CMP** before serving ads to EEA/UK users. The game's
  hand-rolled consent gate is sound engineering and is *not* on Google's
  certified list; that is a hard blocker for EEA/UK ad revenue.
- **Privacy policy and landing-page copy.** Both currently tell visitors
  there are no accounts and no tracking. They must change in the same release
  as the code, not after it.
- **The offline grace window** is set to 30 days in `wrangler.jsonc`
  (`SESSION_DAYS`) as a starting point and has not been decided. Too short and
  "works offline" is a lie; too long and a refunded entitlement keeps working.
