<?php
/* ============================================================
   CARVE API — HTTP helpers
   KG Studio
   ------------------------------------------------------------
   Responses, CORS, session cookies, tokens. Ported from the Workers version;
   the reasoning carried over, the mechanics did not.
   ============================================================ */

declare(strict_types=1);


/* ------------------------------------------------------------
   CORS
   ------------------------------------------------------------
   The game and the API are different ORIGINS but the same SITE (both
   *.futureoftheisles.org), which is the distinction that matters:

   - Different origin → we must echo an explicit Allow-Origin.
   - Same site        → the session cookie can stay SameSite=Lax rather than
                        None, so it is not sent from anywhere else at all.

   Allow-Origin is echoed from an allowlist and never '*'. Browsers silently
   ignore a wildcard when credentials are involved, so using one would look
   permissive while breaking every authenticated request.
   ------------------------------------------------------------ */
function carve_allowed_origins(): array
{
    $raw = carve_setting('allowed_origins', 'https://carve.futureoftheisles.org');
    return array_values(array_filter(array_map('trim', explode(',', (string) $raw))));
}


function carve_request_origin(): ?string
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return null;
    }
    return in_array($origin, carve_allowed_origins(), true) ? $origin : null;
}


function carve_send_cors(): void
{
    $origin = carve_request_origin();
    if ($origin === null) {
        return;
    }

    header('Access-Control-Allow-Origin: ' . $origin);
    header('Access-Control-Allow-Credentials: true');
    /* Without Vary, a shared cache can hand one origin's CORS headers to
       another — a failure that presents as an intermittent browser bug. */
    header('Vary: Origin');
}


function carve_handle_preflight(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'OPTIONS') {
        return;
    }

    if (carve_request_origin() === null) {
        // Refuse without disclosing what the allowlist contains.
        http_response_code(403);
        exit;
    }

    carve_send_cors();
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    header('Access-Control-Max-Age: 86400');
    http_response_code(204);
    exit;
}


/* ------------------------------------------------------------
   Responses
   ------------------------------------------------------------ */
function carve_json(array $body, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    carve_send_cors();
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}


/* Errors carry a machine-readable code and nothing else. No SQL, no paths,
   no upstream text: the client needs to know which case it hit, and an
   attacker should learn nothing about what is behind this. */
function carve_fail(string $error, int $status = 400): void
{
    carve_json(['error' => $error], $status);
}


function carve_redirect(string $location, array $extraHeaders = []): void
{
    foreach ($extraHeaders as $header) {
        header($header, false);
    }
    header('Cache-Control: no-store');
    header('Location: ' . $location, true, 302);
    exit;
}


/* ------------------------------------------------------------
   Tokens
   ------------------------------------------------------------
   random_bytes, not mt_rand or uniqid: those are predictable, and a guessable
   session token is a login-as-anyone bug. random_bytes throws rather than
   silently degrading if no CSPRNG is available, which is the behaviour we
   want on a payment path.
   ------------------------------------------------------------ */
function carve_new_token(): string
{
    return bin2hex(random_bytes(32));
}


/* The raw token goes to the browser; only its SHA-256 is stored. If the
   database leaks, the hashes cannot be replayed as live sessions. */
function carve_hash_token(string $token): string
{
    return hash('sha256', $token);
}


/* ------------------------------------------------------------
   Session cookie
   ------------------------------------------------------------
   Host-only — no Domain attribute — so this is scoped to the API hostname
   alone. Domain=.futureoftheisles.org would send the session token to the
   WordPress site on every request there, which has no business receiving it
   and runs a plugin stack we do not control.
   ------------------------------------------------------------ */
const CARVE_SESSION_COOKIE = 'carve_session';

function carve_set_session_cookie(string $token, int $days): void
{
    setcookie(CARVE_SESSION_COOKIE, $token, [
        'expires'  => time() + ($days * 86400),
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}


function carve_clear_session_cookie(): void
{
    setcookie(CARVE_SESSION_COOKIE, '', [
        'expires'  => time() - 3600,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}


function carve_read_session_token(): ?string
{
    $value = $_COOKIE[CARVE_SESSION_COOKIE] ?? '';
    return $value === '' ? null : (string) $value;
}


/* ------------------------------------------------------------
   Constant-time compare for attacker-supplied secrets.
   hash_equals rather than === : a plain comparison leaks
   position-of-first-difference through timing.
   ------------------------------------------------------------ */
function carve_secrets_match(string $a, string $b): bool
{
    return hash_equals($a, $b);
}
