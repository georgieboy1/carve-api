<?php
/* ============================================================
   CARVE API — front controller
   KG Studio
   ------------------------------------------------------------
   Everything under this webroot routes through here. The application code
   lives one level up, OUTSIDE the webroot, so a webserver misconfiguration
   that stops executing PHP serves nothing useful rather than dumping source
   containing queries and logic.

   ROUTES
     GET  /health          liveness + database reachability
     GET  /auth/google     begin Google sign-in
     GET  /auth/callback   finish sign-in, open a session
     POST /auth/signout    delete the session row
     GET  /entitlement     entitlements + offline grace
     POST /checkout        [next] create a Stripe Checkout Session
     POST /webhook/stripe  [next] checkout.session.completed
     POST /account/delete  [next] GDPR Art.17 — one cascading DELETE
   ============================================================ */

declare(strict_types=1);

/* Errors go to the log, never to the response. A PHP notice rendered into a
   JSON body leaks absolute paths, and on a payment endpoint it can leak
   arguments. display_errors is set here rather than trusted from php.ini
   because shared hosting defaults move without warning. */
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require __DIR__ . '/../src/bootstrap.php';
require __DIR__ . '/../src/http.php';
require __DIR__ . '/../src/auth.php';
require __DIR__ . '/../src/entitlement.php';

/* Any uncaught throwable becomes a bland 500. Without this, a PDOException
   escaping a handler would render its message — which contains the query and
   sometimes the connection string. */
set_exception_handler(static function (Throwable $e): void {
    error_log('carve: uncaught ' . get_class($e) . ': ' . $e->getMessage()
        . ' @ ' . $e->getFile() . ':' . $e->getLine());
    carve_fail('internal_error', 500);
});

carve_handle_preflight();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = '/' . trim((string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH), '/');

switch ($method . ' ' . $path) {
    case 'GET /health':
        carve_health();
        break;

    case 'GET /auth/google':
        carve_auth_begin();
        break;

    case 'GET /auth/callback':
        carve_auth_callback();
        break;

    case 'POST /auth/signout':
        carve_auth_signout();
        break;

    case 'GET /entitlement':
        carve_entitlement_read();
        break;

    default:
        carve_fail('not_found', 404);
}


/* ------------------------------------------------------------
   /health
   ------------------------------------------------------------
   Deliberately touches the database. A service that boots but cannot reach
   MySQL is not healthy, and a check that only proves "PHP replied" reports
   green through exactly the outage that matters.

   Reports migration state too: a reachable but unmigrated database is its own
   failure mode, and the one you hit on a fresh deploy — better read as
   unhealthy than as a puzzling 500 on the first real request.

   Also reports the deployed commit, so "is the fix live yet" is answerable
   without shell access.
   ------------------------------------------------------------ */
function carve_health(): void
{
    $started = microtime(true);

    $stmt = carve_db()->query(
        "SELECT COUNT(*) AS n FROM information_schema.tables
          WHERE table_schema = DATABASE()
            AND table_name IN ('users','entitlements','sessions','processed_events')"
    );
    $tables   = (int) ($stmt->fetch()['n'] ?? 0);
    $migrated = $tables === 4;

    carve_json([
        'ok'       => $migrated,
        'database' => 'reachable',
        'tables'   => $tables,
        'migrated' => $migrated,
        'commit'   => carve_deployed_commit(),
        'query_ms' => (int) round((microtime(true) - $started) * 1000),
    ], $migrated ? 200 : 503);
}


/* Read straight from .git rather than shelling out to git — exec may be
   disabled on shared hosting, and this only needs one file. */
function carve_deployed_commit(): ?string
{
    $head = @file_get_contents(__DIR__ . '/../.git/HEAD');
    if ($head === false) {
        return null;
    }

    if (preg_match('/^ref:\s*(\S+)/', $head, $m)) {
        $sha = @file_get_contents(__DIR__ . '/../.git/' . $m[1]);
        return $sha === false ? null : substr(trim($sha), 0, 7);
    }

    return substr(trim($head), 0, 7);
}
