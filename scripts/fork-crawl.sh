#!/usr/bin/env bash
# ©AngelaMos | 2026
# fork-crawl.sh
# Background fork-graph crawler. Enumerates forks of every known carrier repo,
# dedups forker usernames into a queue, then runs `erinyes sweep` across the
# queue at a safe pace. Idempotent and resumable: the queue file persists
# across runs, and sweep outputs are keyed by owner so re-running skips what
# already landed.
#
# Needs $GITHUB_TOKEN (same token used by `erinyes hunt`).
# Needs `erinyes` on PATH.
# Needs `jq` on PATH.

set -euo pipefail

: "${GITHUB_TOKEN:?set GITHUB_TOKEN before running}"

OUT_DIR="${OUT_DIR:-$HOME/erinyes-sweeps}"
QUEUE_FILE="${QUEUE_FILE:-$OUT_DIR/fork-queue.txt}"
DONE_FILE="${DONE_FILE:-$OUT_DIR/fork-done.txt}"
LOG_FILE="${LOG_FILE:-$OUT_DIR/crawl.log}"
SWEEP_SLEEP_SECONDS="${SWEEP_SLEEP_SECONDS:-45}"
FORK_API_SLEEP_SECONDS="${FORK_API_SLEEP_SECONDS:-2}"
PER_PAGE=100

mkdir -p "$OUT_DIR"
touch "$QUEUE_FILE" "$DONE_FILE" "$LOG_FILE"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG_FILE" >&2; }

CARRIERS=(
  "kloxeld/xscrape"
  "hitechcloud-vietnam/wp2shell-PoC"
  "hitechcloud-vietnam/cve-2026-41940-PoC"
  "hkqr/my-free-code"
  "letorig/video-generator-client"
  "gunkonchi/xscrape"
  "gichirimaku/wp2shell-PoC"
  "Dropnation/contract-fuzzer"
  "tokmakova-nadyubya/sora2-watermark-remover-enchanted"
  "tomateo1reg/sora2-watermark-remover-web-gui"
  "unknown-person00lie/KawaiiGPT"
  "qG5CAsz/walletool"
  "uwctcjnwlk/web3-decoder"
  "versiaever/Pharos-Testnet-Bot"
  "thomasdutraa07/Trading-Bot-for-Binance-Future"
  "yadyvazifeh1oz92/ecdsa-private-key-recovery"
  "watsondonald14/mflowgen"
  "75al-ya/NaorisProtocol-bot"
  "ultiwebtraffidt/openfi-bot"
  "tq17oa7/spyder-osint"
  "tedt8ik31/web3-flashbots"
)

gh_get() {
  local url="$1"
  curl -sf \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$url"
}

enumerate_forks() {
  local carrier="$1"
  local page=1
  log "forks: $carrier (page 1)"
  while :; do
    local body
    body=$(gh_get "https://api.github.com/repos/$carrier/forks?per_page=$PER_PAGE&sort=newest&page=$page") || {
      log "  forks: $carrier page $page: fetch failed, skipping"
      break
    }
    local owners
    owners=$(printf '%s' "$body" | jq -r '.[].owner.login // empty')
    [[ -z "$owners" ]] && break
    printf '%s\n' "$owners" >> "$QUEUE_FILE"
    local count
    count=$(printf '%s\n' "$owners" | wc -l)
    log "  forks: $carrier page $page: +$count owners"
    (( count < PER_PAGE )) && break
    page=$((page+1))
    sleep "$FORK_API_SLEEP_SECONDS"
  done
}

phase_enumerate() {
  log "phase 1: enumerating forks of ${#CARRIERS[@]} carrier repos"
  for c in "${CARRIERS[@]}"; do
    enumerate_forks "$c"
    sleep "$FORK_API_SLEEP_SECONDS"
  done
  sort -u "$QUEUE_FILE" -o "$QUEUE_FILE"
  log "phase 1: queue size $(wc -l < "$QUEUE_FILE") owners"
}

phase_sweep() {
  log "phase 2: sweeping queued owners (pause ${SWEEP_SLEEP_SECONDS}s each)"
  local total done_count=0
  total=$(wc -l < "$QUEUE_FILE")
  while read -r owner; do
    [[ -z "$owner" ]] && continue
    if grep -Fxq "$owner" "$DONE_FILE"; then
      continue
    fi
    done_count=$((done_count+1))
    log "sweep [$done_count/$total]: $owner"
    local report="$OUT_DIR/sweep-$owner.md"
    local code=0
    if erinyes sweep "$owner" \
         --format markdown \
         --output "$report" 2>>"$LOG_FILE"; then
      code=0
    else
      code=$?
    fi
    case "$code" in
      0) printf '%s\n' "$owner" >> "$DONE_FILE" ;;
      1)
        log "  HIT: $owner, see $report"
        printf '%s\n' "$owner" >> "$DONE_FILE"
        ;;
      *) log "  sweep failed for $owner (exit $code, left in queue to retry next run)" ;;
    esac
    sleep "$SWEEP_SLEEP_SECONDS"
  done < "$QUEUE_FILE"
  log "phase 2: complete"
}

main() {
  case "${1:-all}" in
    enum)   phase_enumerate ;;
    sweep)  phase_sweep ;;
    all)    phase_enumerate; phase_sweep ;;
    *)      echo "usage: $0 [enum|sweep|all]" >&2; exit 2 ;;
  esac
}

main "$@"
