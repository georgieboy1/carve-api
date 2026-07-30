/* ============================================================
   CARVE API — entitlement
   KG Studio
   ------------------------------------------------------------
   The one question the game cannot answer for itself.

   THE OFFLINE GRACE, WHICH IS THE WHOLE DESIGN
   Server-side entitlement is what closes the key-sharing hole the sealed
   packs never could. But offline play is shipped and advertised, so a check
   that requires a network every launch would break a real feature to protect
   a $3.99 unlock.

   So this returns `grace_until`. The client caches the answer and honours it
   offline until then. A signed-in owner plays on a plane; the grace lapses if
   they never come back online.

   The window is a judgement call, not a default. Too short and "works
   offline" is a lie. Too long and a refunded entitlement keeps working.
   Currently 30 days, decided 2026-07-29, configured as
   ENTITLEMENT_GRACE_DAYS.

   INVARIANT: grace must never exceed the session lifetime. If it did, a
   client could honour a cached entitlement belonging to a session the server
   has already stopped recognising — trusting a token that no longer exists.
   Asserted below rather than left as a comment.
   ============================================================ */

import { json, fail } from './http.js';
import { currentUser } from './auth.js';

export async function read(request, env) {
  const user = await currentUser(request, env);

  if (!user) {
    /* 401 rather than an empty entitlement list: "not signed in" and "signed
       in and owns nothing" are different states, and the client shows
       different things for them — Sign in versus Buy. */
    return fail('not_signed_in', { status: 401, request, env });
  }

  const { results } = await env.DB.prepare(
    `SELECT sku, granted_at
       FROM entitlements
      WHERE user_id = ? AND revoked_at IS NULL
      ORDER BY granted_at`,
  ).bind(user.id).all();

  const graceDays = graceWindow(env);

  return json({
    email: user.email,
    skus: (results || []).map((r) => r.sku),
    grace_days: graceDays,
    /* Absolute instant, not a duration. A duration has to be added to
       something, and the client's clock is not ours to trust for that. */
    grace_until: new Date(Date.now() + graceDays * 86400_000).toISOString(),
  }, { request, env, headers: { 'cache-control': 'no-store' } });
}


/* Clamped to the session lifetime, and says so in the log if it had to
   clamp — a misconfiguration that silently weakens the guarantee is worse
   than one that complains. */
function graceWindow(env) {
  const grace = Number(env.ENTITLEMENT_GRACE_DAYS ?? 30);
  const session = Number(env.SESSION_DAYS ?? 30);

  if (!Number.isFinite(grace) || grace <= 0) return 0;

  if (grace > session) {
    console.warn(
      `ENTITLEMENT_GRACE_DAYS (${grace}) exceeds SESSION_DAYS (${session}); ` +
      `clamping to ${session}. A grace longer than the session would have the ` +
      `client trusting an entitlement whose session no longer exists.`);
    return session;
  }

  return grace;
}
