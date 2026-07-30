/* ============================================================
   CARVE API — HTTP helpers
   KG Studio
   ------------------------------------------------------------
   Response shaping and CORS. Small on purpose: this sits in front of the
   payment path, so there is no framework here to have opinions we did not
   ask for.
   ============================================================ */

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };


/* ------------------------------------------------------------
   CORS
   ------------------------------------------------------------
   The game and the API are different ORIGINS (carve. vs api.) so CORS is
   required — but they are the same SITE (both *.futureoftheisles.org), which
   is a distinction worth holding onto:

   - Different origin  → we must echo an explicit Allow-Origin.
   - Same site         → the session cookie can stay SameSite=Lax rather than
                         SameSite=None, so it is not sent on genuinely
                         cross-site requests from anywhere else.

   Allow-Origin is echoed from an allowlist and never '*'. A wildcard is
   silently ignored by browsers when credentials are involved, so using one
   would look permissive while breaking every authenticated request.
   ------------------------------------------------------------ */
export function allowedOrigin(request, env) {
  const origin = request.headers.get('Origin');
  if (!origin) return null;

  const list = String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  return list.includes(origin) ? origin : null;
}


export function corsHeaders(request, env) {
  const origin = allowedOrigin(request, env);
  if (!origin) return {};

  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    /* Tell caches the response body varies by Origin. Without this a shared
       cache can serve one origin's CORS headers to another, which fails in a
       way that looks like an intermittent browser bug. */
    vary: 'Origin',
  };
}


export function preflight(request, env) {
  if (!allowedOrigin(request, env)) {
    // Unknown origin: refuse without saying what the allowlist contains.
    return new Response(null, { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      ...corsHeaders(request, env),
      'access-control-allow-methods': 'GET, POST, OPTIONS',
      'access-control-allow-headers': 'content-type',
      'access-control-max-age': '86400',
    },
  });
}


/* ------------------------------------------------------------
   Responses
   ------------------------------------------------------------ */

export function json(body, { status = 200, request, env, headers = {} } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...(request ? corsHeaders(request, env) : {}),
      ...headers,
    },
  });
}


/* Errors carry a machine-readable `error` and nothing else. No stack traces,
   no SQL, no upstream text: a client needs to know which case it hit, and an
   attacker should learn nothing about what is behind this. */
export function fail(error, { status = 400, request, env } = {}) {
  return json({ error }, { status, request, env });
}


/* ------------------------------------------------------------
   Session cookie
   ------------------------------------------------------------
   Host-only — no Domain attribute — so the cookie is scoped to the API
   hostname alone. Setting Domain=.futureoftheisles.org would also send this
   session token to the WordPress site on every request there, which has no
   business receiving it and runs a plugin stack we do not control.
   ------------------------------------------------------------ */
export function sessionCookie(token, { days = 30 } = {}) {
  const maxAge = Math.round(days * 24 * 60 * 60);
  return [
    `carve_session=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
  ].join('; ');
}


export function clearedSessionCookie() {
  return 'carve_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
}


export function readSessionToken(request) {
  const header = request.headers.get('Cookie');
  if (!header) return null;

  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === 'carve_session') return rest.join('=') || null;
  }
  return null;
}


/* ------------------------------------------------------------
   Tokens
   ------------------------------------------------------------
   The raw token goes to the browser; only its SHA-256 is stored. If the
   database leaks, the hashes cannot be replayed as live sessions.
   ------------------------------------------------------------ */
export function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}


export async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(token));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}
