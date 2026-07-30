<?php
/* ============================================================
   CARVE API — bootstrap
   KG Studio
   ------------------------------------------------------------
   Config loading and the database handle. Required by everything.

   The config file lives OUTSIDE the repo and OUTSIDE the webroot, at
   /home1/fxxfjgmy/carve-config.ini (mode 0600). It holds the database
   password and, later, the Google and Stripe secrets. Nothing secret is ever
   committed — the repo is public, deliberately, so the server can pull it
   with no credentials stored on shared hosting.
   ============================================================ */

declare(strict_types=1);

const CARVE_CONFIG_PATH = '/home1/fxxfjgmy/carve-config.ini';


function carve_config(): array
{
    static $config = null;
    if ($config !== null) {
        return $config;
    }

    if (!is_readable(CARVE_CONFIG_PATH)) {
        /* Fail loudly in the log and blandly to the caller. A missing config
           is an operator problem, and the response must not hint at paths. */
        error_log('carve: config unreadable at ' . CARVE_CONFIG_PATH);
        carve_fail('server_misconfigured', 503);
    }

    $parsed = parse_ini_file(CARVE_CONFIG_PATH, false, INI_SCANNER_TYPED);
    if ($parsed === false) {
        error_log('carve: config failed to parse');
        carve_fail('server_misconfigured', 503);
    }

    $config = $parsed;
    return $config;
}


function carve_setting(string $key, ?string $default = null): ?string
{
    $config = carve_config();
    $value = $config[$key] ?? $default;
    return $value === null ? null : (string) $value;
}


/* ------------------------------------------------------------
   Database
   ------------------------------------------------------------
   ERRMODE_EXCEPTION so a failed statement throws rather than returning false
   and letting the next line act on nothing. EMULATE_PREPARES off so real
   server-side placeholders are used — with emulation on, PDO interpolates
   client-side, which is both slower and a wider surface for quoting mistakes.
   ------------------------------------------------------------ */
function carve_db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $config = carve_config();

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $config['db_host'] ?? 'localhost',
        $config['db_name'] ?? '',
    );

    try {
        $pdo = new PDO($dsn, (string) ($config['db_user'] ?? ''), (string) ($config['db_pass'] ?? ''), [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $e) {
        /* Never let the driver message reach the client: it contains the
           user, host and database name, and sometimes the password. */
        error_log('carve: db connect failed: ' . $e->getMessage());
        carve_fail('database_unavailable', 503);
    }

    return $pdo;
}


/* ------------------------------------------------------------
   Time
   ------------------------------------------------------------
   One UTC clock for the whole service. MySQL's NOW() follows the session
   time zone and PHP's follows php.ini, and on shared hosting those disagree
   more often than not — a session written with one and compared against the
   other expires early or late by hours. So timestamps are generated here, in
   UTC, and MySQL only ever stores what it is given.
   ------------------------------------------------------------ */
function carve_now(): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
}


function carve_now_plus_days(int $days): string
{
    return (new DateTimeImmutable('now', new DateTimeZone('UTC')))
        ->add(new DateInterval('P' . max(0, $days) . 'D'))
        ->format('Y-m-d H:i:s');
}
