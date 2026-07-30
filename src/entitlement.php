<?php
/* ============================================================
   CARVE API — entitlement
   KG Studio
   ------------------------------------------------------------
   The one question the game cannot answer for itself.

   THE OFFLINE GRACE, WHICH IS THE WHOLE DESIGN
   Server-side entitlement closes the key-sharing hole the sealed packs never
   could. But offline play is shipped and advertised, so a check that needed a
   network every launch would break a real feature to protect a $3.99 unlock.

   So this returns `grace_until`. The client caches the answer and honours it
   offline until then. A signed-in owner plays on a plane; the grace lapses if
   they never come back online.

   30 days, decided 2026-07-29. Too short and "works offline" is a lie; too
   long and a refunded entitlement keeps working.

   INVARIANT: grace must never exceed the session lifetime, or the client
   would honour an entitlement whose session the server has already stopped
   recognising. Clamped below rather than left as a comment.
   ============================================================ */

declare(strict_types=1);


function carve_entitlement_read(): void
{
    $user = carve_current_user();

    if ($user === null) {
        /* 401, not an empty list. "Not signed in" and "signed in and owns
           nothing" are different states and the client shows different things
           for them — Sign in versus Buy. */
        carve_fail('not_signed_in', 401);
    }

    $stmt = carve_db()->prepare(
        'SELECT sku, granted_at
           FROM entitlements
          WHERE user_id = :user AND revoked_at IS NULL
          ORDER BY granted_at'
    );
    $stmt->execute(['user' => (int) $user['id']]);

    $skus = array_map(
        static fn(array $row): string => (string) $row['sku'],
        $stmt->fetchAll()
    );

    $graceDays = carve_grace_days();

    carve_json([
        'email'       => (string) $user['email'],
        'skus'        => $skus,
        'grace_days'  => $graceDays,
        /* Absolute instant, not a duration. A duration has to be added to
           something, and the client's clock is not ours to trust for that. */
        'grace_until' => (new DateTimeImmutable('now', new DateTimeZone('UTC')))
            ->add(new DateInterval('P' . $graceDays . 'D'))
            ->format(DateTimeInterface::ATOM),
    ]);
}


/* Clamped to the session lifetime, and logged if it had to clamp — a
   misconfiguration that silently weakens the guarantee is worse than one
   that complains. */
function carve_grace_days(): int
{
    $grace   = (int) carve_setting('entitlement_grace_days', '30');
    $session = (int) carve_setting('session_days', '30');

    if ($grace <= 0) {
        return 0;
    }

    if ($grace > $session) {
        error_log(sprintf(
            'carve: entitlement_grace_days (%d) exceeds session_days (%d); clamping to %d. '
            . 'A longer grace would have the client trusting an entitlement whose session no longer exists.',
            $grace, $session, $session
        ));
        return $session;
    }

    return $grace;
}
