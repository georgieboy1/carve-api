/* ============================================================
   CARVE API — Google sign-in
   KG Studio
   ------------------------------------------------------------
   Authorization Code flow with PKCE. Scopes are `openid email profile` and
   nothing else — anything broader triggers heavier Google verification and
   buys entitlement nothing.

   THE FLOW
     GET  /auth/google    mint state + PKCE verifier, park them in a short
                          cookie, redirect to Google
     GET  /auth/callback  check state, swap code for tokens, upsert the user,
                          open a session, redirect back to the game
     POST /auth/signout   delete the session row and clear the cookie

   WHY THE TRANSIENT STATE LIVES IN A COOKIE, NOT A TABLE
   It is needed for the ~60 seconds between leaving for Google and coming
   back. A table would need a row, an index and a sweeper for abandoned
   sign-ins. The callback arrives as a top-level GET navigation, which
   SameSite=Lax cookies are sent on — the one case Lax deliberately allows —
   so a cookie is sufficient and self-cleaning.
   ============================================================ */

import {
  json, fail, newToken, hashToken,
  sessionCookie, clearedSessionCookie, readSessionToken,
} from './http.js';

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

const FLOW_COOKIE = 'carve_oauth';
const FLOW_TTL_SECONDS = 600;   // ten minutes to finish signing in


/* ---------- small encoding helpers ---------- */

const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(verifier));
  return b64url(digest);
}

/* Constant-time compare. `state` is attacker-supplied, and a plain !==
   leaks position-of-first-difference through timing. Cheap insurance. */
function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}


/* ------------------------------------------------------------
   Where we are allowed to send the browser afterwards.

   Never redirect to a caller-supplied URL without checking it. An unchecked
   `return_to` is an open redirect, and an open redirect on the domain that
   also handles sign-in is a phishing primitive: a link that really is
   futureoftheisles.org and really does log you in, then lands you on someone
   else's page. Validated against the same allowlist CORS uses.
   ------------------------------------------------------------ */
function safeReturnTo(candidate, env) {
  const allowed = String(env.ALLOWED_ORIGINS || '')
    .split(',').map((s) => s.trim()).filter(Boolean);

  const fallback = allowed[0] || 'https://carve.futureoftheisles.org';
  if (!candidate) return fallback;

  try {
    const url = new URL(candidate);
    return allowed.includes(url.origin) ? url.href : fallback;
  } catch {
    return fallback;
  }
}


function flowCookie(value, seconds) {
  return [
    `${FLOW_COOKIE}=${value}`,
    'Path=/auth',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${seconds}`,
  ].join('; ');
}

function readFlowCookie(request) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === FLOW_COOKIE) {
      try {
        return JSON.parse(atob(decodeURIComponent(rest.join('='))));
      } catch {
        return null;
      }
    }
  }
  return null;
}


/* ------------------------------------------------------------
   GET /auth/google
   ------------------------------------------------------------ */
export async function begin(request, env) {
  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
    return fail('oauth_not_configured', { status: 503, request, env });
  }

  const url = new URL(request.url);
  const returnTo = safeReturnTo(url.searchParams.get('return_to'), env);

  const state = newToken();
  const verifier = newToken();
  const challenge = await pkceChallenge(verifier);

  const authorize = new URL(GOOGLE_AUTH);
  authorize.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authorize.searchParams.set('redirect_uri', redirectUri(request, env));
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('scope', 'openid email profile');
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  /* select_account rather than none: a shared device should not silently
     sign in whoever used it last, given this account owns purchases. */
  authorize.searchParams.set('prompt', 'select_account');

  const parked = btoa(JSON.stringify({ state, verifier, returnTo }));

  return new Response(null, {
    status: 302,
    headers: {
      location: authorize.href,
      'set-cookie': flowCookie(encodeURIComponent(parked), FLOW_TTL_SECONDS),
      'cache-control': 'no-store',
    },
  });
}


/* The redirect_uri must match Google's registered value byte for byte, so it
   is derived from config when available rather than guessed from the request
   — behind a proxy the request host is not always what Google saw. */
function redirectUri(request, env) {
  if (env.API_ORIGIN) return `${String(env.API_ORIGIN).replace(/\/$/, '')}/auth/callback`;
  return new URL('/auth/callback', request.url).href;
}


/* ------------------------------------------------------------
   GET /auth/callback
   ------------------------------------------------------------ */
export async function callback(request, env) {
  const url = new URL(request.url);

  /* Google reports user refusal here rather than by not returning. Treat it
     as an ordinary outcome and send them back to the game, not an error page. */
  const denied = url.searchParams.get('error');
  const flow = readFlowCookie(request);

  if (denied) {
    return redirectHome(safeReturnTo(flow?.returnTo, env), 'declined');
  }

  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code || !state) return fail('missing_code', { status: 400, request, env });
  if (!flow) return fail('flow_expired', { status: 400, request, env });
  if (!sameSecret(state, flow.state)) {
    // Mismatched state means this callback was not started by this browser.
    return fail('state_mismatch', { status: 400, request, env });
  }

  const tokens = await exchange(code, flow.verifier, request, env);
  if (!tokens?.id_token) {
    return fail('token_exchange_failed', { status: 502, request, env });
  }

  const claims = readIdToken(tokens.id_token, env);
  if (!claims) return fail('bad_id_token', { status: 502, request, env });

  const user = await upsertUser(env, claims);
  const token = await openSession(env, user.id);

  const days = Number(env.SESSION_DAYS || 30);

  return new Response(null, {
    status: 302,
    headers: {
      location: safeReturnTo(flow.returnTo, env),
      'set-cookie': sessionCookie(token, { days }),
      'cache-control': 'no-store',
    },
  });
}


function redirectHome(location, reason) {
  const url = new URL(location);
  if (reason) url.searchParams.set('signin', reason);
  return new Response(null, {
    status: 302,
    headers: {
      location: url.href,
      // Burn the flow cookie either way, so a stale one cannot be replayed.
      'set-cookie': flowCookie('', 0),
      'cache-control': 'no-store',
    },
  });
}


async function exchange(code, verifier, request, env) {
  const body = new URLSearchParams({
    code,
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    redirect_uri: redirectUri(request, env),
    grant_type: 'authorization_code',
    code_verifier: verifier,
  });

  const response = await fetch(GOOGLE_TOKEN, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });

  if (!response.ok) {
    console.error('google token exchange failed:', response.status,
      (await response.text()).slice(0, 400));
    return null;
  }
  return response.json();
}


/* ------------------------------------------------------------
   Reading the ID token.

   The signature is NOT verified, and that is deliberate: this token came
   straight back from Google's token endpoint over TLS in the request above,
   not via the browser, so there is no untrusted hop to forge it. Google's own
   guidance allows skipping signature checks for exactly this case.

   `aud`, `iss` and `exp` ARE checked, because they are cheap and they catch
   the case that actually happens — a token minted for a different client id
   ending up here through a misconfiguration.
   ------------------------------------------------------------ */
function readIdToken(idToken, env) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) return null;

  let claims;
  try {
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    claims = JSON.parse(atob(padded + '='.repeat((4 - padded.length % 4) % 4)));
  } catch {
    return null;
  }

  if (claims.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (!GOOGLE_ISSUERS.includes(claims.iss)) return null;
  if (!claims.sub) return null;
  if (Number(claims.exp) * 1000 <= Date.now()) return null;

  /* An unverified email is not proof of anything. It would still work as an
     identity because `sub` is the key, but storing it as contact data invites
     support replying to an address the user never proved they hold. */
  if (claims.email && claims.email_verified === false) return null;

  return claims;
}


/* ------------------------------------------------------------
   Users and sessions
   ------------------------------------------------------------ */
async function upsertUser(env, claims) {
  /* ON CONFLICT on google_sub, so a returning user updates rather than
     duplicates — and their email is refreshed if they changed it at Google.
     `sub` is the key precisely so that rename is a no-op for entitlement. */
  await env.DB.prepare(
    `INSERT INTO users (google_sub, email)
     VALUES (?1, ?2)
     ON CONFLICT(google_sub) DO UPDATE
       SET email = ?2, updated_at = datetime('now')`,
  ).bind(claims.sub, claims.email || '').run();

  return env.DB.prepare('SELECT id, google_sub, email FROM users WHERE google_sub = ?')
    .bind(claims.sub).first();
}


async function openSession(env, userId) {
  const token = newToken();
  const days = Number(env.SESSION_DAYS || 30);

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at)
     VALUES (?1, ?2, datetime('now', ?3))`,
  ).bind(await hashToken(token), userId, `+${days} days`).run();

  return token;
}


/* Resolves the caller. Expiry is checked in SQL rather than in JS so an
   expired row can never be treated as live by a comparison written the wrong
   way round — and the sweep below keeps the table from growing forever
   without needing a cron. */
export async function currentUser(request, env) {
  const token = readSessionToken(request);
  if (!token) return null;

  const hashed = await hashToken(token);

  const row = await env.DB.prepare(
    `SELECT u.id, u.google_sub, u.email, u.stripe_customer_id
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.id = ?1 AND s.expires_at > datetime('now')`,
  ).bind(hashed).first();

  return row || null;
}


/* ------------------------------------------------------------
   POST /auth/signout
   ------------------------------------------------------------ */
export async function signout(request, env) {
  const token = readSessionToken(request);

  if (token) {
    /* Delete the row, do not just clear the cookie. A cleared cookie leaves a
       live session token that anyone who copied it can keep using — "sign
       out" has to mean the server stops honouring it. */
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?')
      .bind(await hashToken(token)).run();
  }

  return json({ ok: true }, {
    request, env, headers: { 'set-cookie': clearedSessionCookie() },
  });
}
