#!/bin/sh
# ============================================================
# CARVE API — pull deploy
# KG Studio
# ------------------------------------------------------------
# Run from cron on the Bluehost box. Fetches origin/main and, only if the
# remote actually moved, resets the working tree to match it.
#
# This is the deploy pipeline. Shared hosting has no build hooks, so the
# server pulls rather than something pushing to the server. Two useful
# consequences:
#
#  - What is running always corresponds to a commit, so a bad deploy is
#    `git revert` plus two minutes rather than an archaeology session.
#  - The Agent Connector refuses to let an agent write .php or .htaccess
#    outside its sandbox. Git writing those files is not that, so the code
#    path an agent uses to ship is the same one a human uses, with review
#    history attached.
#
# `reset --hard` is deliberate: this checkout is a deploy target, not a place
# to work. Anything edited here by hand SHOULD be destroyed on the next pull,
# because the alternative is a server quietly diverging from the repo and
# nobody knowing which is real.
# ============================================================

set -eu

REPO="/home1/fxxfjgmy/carve-api"
BRANCH="main"
LOG="/home1/fxxfjgmy/logs/carve-deploy.log"

mkdir -p "$(dirname "$LOG")"

log() {
    printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" >> "$LOG"
}

cd "$REPO" || { log "FATAL repo missing at $REPO"; exit 1; }

# Fail quietly on a network blip: cron will try again shortly, and a noisy
# failure every two minutes during an outage buries the real errors.
if ! git fetch --quiet origin "$BRANCH" 2>/dev/null; then
    log "fetch failed (network?) — will retry"
    exit 0
fi

LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse "origin/$BRANCH")"

if [ "$LOCAL" = "$REMOTE" ]; then
    exit 0    # nothing to do, and nothing worth logging every two minutes
fi

log "deploying $(echo "$LOCAL" | cut -c1-7) -> $(echo "$REMOTE" | cut -c1-7)"

# Lint before swapping anything in. A PHP parse error in the front controller
# takes down every route at once, including the Stripe webhook — and Stripe
# retries a failing webhook for days, so a broken deploy is not self-limiting.
TMP="$(mktemp -d)"
if git archive "origin/$BRANCH" | tar -x -C "$TMP" 2>/dev/null; then
    BAD=0
    for f in "$TMP"/src/*.php "$TMP"/public/*.php; do
        [ -f "$f" ] || continue
        if ! php -l "$f" >/dev/null 2>&1; then
            log "REFUSED: syntax error in $(basename "$f") — keeping $(echo "$LOCAL" | cut -c1-7)"
            BAD=1
        fi
    done
    rm -rf "$TMP"
    [ "$BAD" -eq 0 ] || exit 1
else
    rm -rf "$TMP"
    log "could not stage archive for linting — proceeding without lint"
fi

git reset --hard --quiet "origin/$BRANCH"

# Confirm the thing that matters, rather than assuming the reset was enough.
if HEALTH="$(curl -fsS --max-time 15 https://api.futureoftheisles.org/health 2>/dev/null)"; then
    log "deployed $(echo "$REMOTE" | cut -c1-7) — health: $HEALTH"
else
    log "WARNING deployed $(echo "$REMOTE" | cut -c1-7) but /health did not return 200"
fi
