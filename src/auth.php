<?php
/* ============================================================
   CARVE API — Google sign-in
   KG Studio
   ------------------------------------------------------------
   Authorization Code flow with PKCE. Scopes are `openid email profile` and
   nothing else — anything broader triggers heavier Google verification and
   buys entitlement nothing.

     GET  /auth/google    mint state + PKCE verifier, park them in a short
                          cookie, redirect to Google
     GET  /auth/callback  check state, swap code for tokens, upsert the user,
                          open a session, redirect back to the game
     POST /auth/signout   delete the session row and clear the cookie

   The transient state lives in a ten-minute cookie rather than a table. It is
   only needed for the ~60 seconds between leaving for Google and coming back;
   a table would want a row, an index and a sweeper for abandoned sign-ins.
   The callback arrives as a top-level GET navigation, which is precisely the
   case SameSite=Lax allows, so a cookie is sufficient and self-cleaning.
   ============================================================ */

declare(strict_types=1);

const CARVE_GOOGLE_AUTH  = 'https://accounts.google.com/o/oauth2/v2/auth';
const CARVE_GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const CARVE_GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

const CARVE_FLOW_COOKIE = 'carve_oauth';
const CARVE_FLOW_TTL    = 600;


function carve_b64url(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function carve_b64url_decode(string $value): string
{
    $padded = strtr($value, '-_', '+/');
    return (string) base64_decode($padded . str_repeat('=', (4 - strlen($padded) % 4) % 4));
}


/* ------------------------------------------------------------
   Where we may send the browser afterwards.

   Never redirect to a caller-supplied URL without checking it. An unchecked
   return_to is an open redirect, and an open redirect on the domain that also
   handles sign-in is a phishing primitive: a link that really is ours, really
   logs you in, then lands you on someone else's page.
   ------------------------------------------------------------ */
function carve_safe_return_to(?string $candidate): string
{
    $allowed  = carve_allowed_origins();
    $fallback = $allowed[0] ?? 'https://carve.futureoftheisles.org';

    if ($candidate === null || $candidate === '') {
        return $fallback;
    }

    $parts = parse_url($candidate);
    if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
        return $fallback;
    }

    $origin = $parts['scheme'] . '://' . $parts['host']
        . (isset($parts['port']) ? ':' . $parts['port'] : '');

    return in_array($origin, $allowed, true) ? $candidate : $fallback;
}


function carve_redirect_uri(): string
{
    /* Configured, not inferred from the request. Google requires redirect_uri
       to match its registered value byte for byte, and behind a proxy the
       request host is not always what Google saw. */
    $origin = rtrim((string) carve_setting('api_origin', ''), '/');
    return $origin . '/auth/callback';
}


function carve_flow_cookie_set(array $payload): void
{
    setcookie(CARVE_FLOW_COOKIE, carve_b64url(json_encode($payload, JSON_THROW_ON_ERROR)), [
        'expires'  => time() + CARVE_FLOW_TTL,
        'path'     => '/auth',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function carve_flow_cookie_clear(): void
{
    setcookie(CARVE_FLOW_COOKIE, '', [
        'expires' => time() - 3600, 'path' => '/auth',
        'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
    ]);
}

function carve_flow_cookie_read(): ?array
{
    $raw = $_COOKIE[CARVE_FLOW_COOKIE] ?? '';
    if ($raw === '') {
        return null;
    }
    $decoded = json_decode(carve_b64url_decode((string) $raw), true);
    return is_array($decoded) ? $decoded : null;
}


/* ------------------------------------------------------------
   GET /auth/google
   ------------------------------------------------------------ */
function carve_auth_begin(): void
{
    $clientId = carve_setting('google_client_id', '');
    if ($clientId === '' || carve_setting('google_client_secret', '') === '') {
        carve_fail('oauth_not_configured', 503);
    }

    $state    = carve_new_token();
    $verifier = carve_new_token();
    $returnTo = carve_safe_return_to($_GET['return_to'] ?? null);

    carve_flow_cookie_set([
        'state'    => $state,
        'verifier' => $verifier,
        'returnTo' => $returnTo,
    ]);

    $query = http_build_query([
        'client_id'             => $clientId,
        'redirect_uri'          => carve_redirect_uri(),
        'response_type'         => 'code',
        'scope'                 => 'openid email profile',
        'state'                 => $state,
        'code_challenge'        => carve_b64url(hash('sha256', $verifier, true)),
        'code_challenge_method' => 'S256',
        /* select_account, not none: a shared device should not silently sign
           in whoever used it last, given this account owns purchases. */
        'prompt'                => 'select_account',
    ]);

    carve_redirect(CARVE_GOOGLE_AUTH . '?' . $query);
}


/* ------------------------------------------------------------
   GET /auth/callback
   ------------------------------------------------------------ */
function carve_auth_callback(): void
{
    $flow = carve_flow_cookie_read();

    /* Google reports refusal here rather than by not returning. Treat it as
       an ordinary outcome and send them back to the game, not an error page. */
    if (isset($_GET['error'])) {
        carve_flow_cookie_clear();
        $home = carve_safe_return_to($flow['returnTo'] ?? null);
        carve_redirect($home . (str_contains($home, '?') ? '&' : '?') . 'signin=declined');
    }

    $code  = (string) ($_GET['code'] ?? '');
    $state = (string) ($_GET['state'] ?? '');

    if ($code === '' || $state === '') {
        carve_fail('missing_code', 400);
    }
    if ($flow === null) {
        carve_fail('flow_expired', 400);
    }
    if (!carve_secrets_match($state, (string) ($flow['state'] ?? ''))) {
        // Mismatched state means this callback was not started by this browser.
        carve_fail('state_mismatch', 400);
    }

    $tokens = carve_google_exchange($code, (string) $flow['verifier']);
    if ($tokens === null || !isset($tokens['id_token'])) {
        carve_fail('token_exchange_failed', 502);
    }

    $claims = carve_read_id_token((string) $tokens['id_token']);
    if ($claims === null) {
        carve_fail('bad_id_token', 502);
    }

    $userId = carve_upsert_user($claims);
    $token  = carve_open_session($userId);

    carve_flow_cookie_clear();
    carve_set_session_cookie($token, (int) carve_setting('session_days', '30'));
    carve_redirect(carve_safe_return_to($flow['returnTo'] ?? null));
}


function carve_google_exchange(string $code, string $verifier): ?array
{
    $body = http_build_query([
        'code'          => $code,
        'client_id'     => carve_setting('google_client_id', ''),
        'client_secret' => carve_setting('google_client_secret', ''),
        'redirect_uri'  => carve_redirect_uri(),
        'grant_type'    => 'authorization_code',
        'code_verifier' => $verifier,
    ]);

    $ch = curl_init(CARVE_GOOGLE_TOKEN);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $body,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        // Defaults are already strict, but a downgrade here would be silent.
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
    ]);

    $response = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $error    = curl_error($ch);
    curl_close($ch);

    if ($response === false || $status !== 200) {
        error_log('carve: google token exchange failed: ' . $status . ' ' . $error
            . ' ' . substr((string) $response, 0, 300));
        return null;
    }

    $decoded = json_decode((string) $response, true);
    return is_array($decoded) ? $decoded : null;
}


/* ------------------------------------------------------------
   Reading the ID token.

   The signature is NOT verified, deliberately: this token came straight back
   from Google's token endpoint over TLS in the request above, not via the
   browser, so there is no untrusted hop on which to forge it. Google's own
   guidance allows skipping signature checks for exactly this case.

   aud, iss and exp ARE checked — cheap, and they catch the thing that
   actually happens: a token minted for a different client id arriving here
   through a misconfiguration.
   ------------------------------------------------------------ */
function carve_read_id_token(string $idToken): ?array
{
    $parts = explode('.', $idToken);
    if (count($parts) !== 3) {
        return null;
    }

    $claims = json_decode(carve_b64url_decode($parts[1]), true);
    if (!is_array($claims)) {
        return null;
    }

    if (($claims['aud'] ?? null) !== carve_setting('google_client_id', '')) {
        return null;
    }
    if (!in_array($claims['iss'] ?? '', CARVE_GOOGLE_ISSUERS, true)) {
        return null;
    }
    if (empty($claims['sub'])) {
        return null;
    }
    if ((int) ($claims['exp'] ?? 0) <= time()) {
        return null;
    }

    /* An unverified email proves nothing. `sub` is the identity so sign-in
       would still work, but storing it as contact data invites support
       replying to an address the user never proved they hold. */
    if (isset($claims['email']) && ($claims['email_verified'] ?? true) === false) {
        return null;
    }

    return $claims;
}


/* ------------------------------------------------------------
   Users and sessions
   ------------------------------------------------------------ */
function carve_upsert_user(array $claims): int
{
    $db = carve_db();

    /* ON DUPLICATE KEY on google_sub, so a returning user updates rather than
       duplicates — and their email refreshes if they changed it at Google.
       `sub` is the key precisely so that rename is a no-op for entitlement. */
    $db->prepare(
        'INSERT INTO users (google_sub, email, created_at, updated_at)
         VALUES (:sub, :email, :now, :now)
         ON DUPLICATE KEY UPDATE email = VALUES(email), updated_at = VALUES(updated_at)'
    )->execute([
        'sub'   => (string) $claims['sub'],
        'email' => (string) ($claims['email'] ?? ''),
        'now'   => carve_now(),
    ]);

    $stmt = $db->prepare('SELECT id FROM users WHERE google_sub = :sub');
    $stmt->execute(['sub' => (string) $claims['sub']]);
    $row = $stmt->fetch();

    if ($row === false) {
        carve_fail('user_upsert_failed', 500);
    }

    return (int) $row['id'];
}


function carve_open_session(int $userId): string
{
    $token = carve_new_token();
    $days  = (int) carve_setting('session_days', '30');

    carve_db()->prepare(
        'INSERT INTO sessions (id, user_id, created_at, expires_at)
         VALUES (:id, :user, :now, :expires)'
    )->execute([
        'id'      => carve_hash_token($token),
        'user'    => $userId,
        'now'     => carve_now(),
        'expires' => carve_now_plus_days($days),
    ]);

    return $token;
}


/* Resolves the caller. Expiry is compared in SQL against a UTC timestamp we
   generate, not against MySQL's NOW() — see carve_now() for why mixing the
   two clocks silently shifts every expiry by the timezone offset. */
function carve_current_user(): ?array
{
    $token = carve_read_session_token();
    if ($token === null) {
        return null;
    }

    $stmt = carve_db()->prepare(
        'SELECT u.id, u.google_sub, u.email, u.stripe_customer_id
           FROM sessions s
           JOIN users u ON u.id = s.user_id
          WHERE s.id = :id AND s.expires_at > :now'
    );
    $stmt->execute(['id' => carve_hash_token($token), 'now' => carve_now()]);

    $row = $stmt->fetch();
    return $row === false ? null : $row;
}


/* ------------------------------------------------------------
   POST /auth/signout
   ------------------------------------------------------------ */
function carve_auth_signout(): void
{
    $token = carve_read_session_token();

    if ($token !== null) {
        /* DELETE the row, do not merely clear the cookie. A cleared cookie
           leaves a live token that anyone who copied it can keep using —
           "sign out" has to mean the server stops honouring it. */
        carve_db()->prepare('DELETE FROM sessions WHERE id = :id')
            ->execute(['id' => carve_hash_token($token)]);
    }

    carve_clear_session_cookie();
    carve_json(['ok' => true]);
}
