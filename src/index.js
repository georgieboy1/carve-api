/* ============================================================
   CARVE API — entry point
   KG Studio
   ------------------------------------------------------------
   Entitlement service for Carve. Answers one question the client cannot
   answer for itself: is this signed-in person allowed to play the paid
   collections?

   That is the whole reason this exists. The previous design sealed the paid
   levels behind a single shared passphrase, which could never stop a buyer
   redistributing it — the key had to reach their machine to work. Moving
   entitlement to a server they do not control closes that.

   STEP 1 of the build (see blueprint.md): platform, schema, deploy pipeline.
   Nothing user-visible. Sign-in and Stripe land in steps 2 and 3; the router
   below marks exactly where.

   ROUTES
     GET  /health          liveness + database reachability
     GET  /auth/google     [step 2] begin sign-in
     GET  /auth/callback   [step 2] finish sign-in
     POST /auth/signout    [step 2]
     GET  /entitlement     [step 2] the signed-in user's entitlements
     POST /checkout        [step 3] create a Stripe Checkout Session
     POST /webhook/stripe  [step 3] checkout.session.completed
     POST /account/delete  [step 4] GDPR Art.17 — one cascading DELETE
   ============================================================ */

import { json, fail, preflight } from './http.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;

    if (request.method === 'OPTIONS') return preflight(request, env);

    try {
      switch (route) {
        case 'GET /health':
          return await health(request, env);

        default:
          return fail('not_found', { status: 404, request, env });
      }
    } catch (error) {
      /* Log the real error where only we can see it; return a bare code.
         On a payment path the postmortem matters more than the response body,
         and the response body must never carry SQL or a stack trace. */
      console.error(`${route} failed:`, error?.stack || error);
      return fail('internal_error', { status: 500, request, env });
    }
  },
};


/* ------------------------------------------------------------
   /health
   ------------------------------------------------------------
   Deliberately touches the database. A worker that boots but cannot reach D1
   is not healthy, and a check that only proves "the worker replied" reports
   green through exactly the outage that matters.

   Reports migration state too. A reachable but unmigrated database is its own
   failure mode, and it is the one you hit on a fresh deploy — so it should
   read as unhealthy rather than as a puzzling 500 on the first real request.
   ------------------------------------------------------------ */
async function health(request, env) {
  if (!env.DB) {
    return json({ ok: false, database: 'unbound' },
      { status: 503, request, env });
  }

  const started = Date.now();

  const row = await env.DB
    .prepare(`SELECT count(*) AS n FROM sqlite_master
              WHERE type = 'table' AND name IN
                ('users', 'entitlements', 'sessions', 'processed_events')`)
    .first();

  const tables = row?.n ?? 0;
  const migrated = tables === 4;

  return json({
    ok: migrated,
    database: 'reachable',
    tables,
    migrated,
    query_ms: Date.now() - started,
  }, { status: migrated ? 200 : 503, request, env });
}
