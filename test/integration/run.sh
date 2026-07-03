#!/usr/bin/env bash
# Real-kernel integration tests for nft-blocklist.
#
# Why namespaces: `nft` needs CAP_NET_ADMIN, but these tests must run on
# developer laptops and CI without sudo and without touching the host
# firewall. By default `unshare -r -n` provides root + a private network
# namespace, so every nft command here operates on a throwaway kernel table and
# the feed server binds only to the namespace's loopback. CI can set
# NFTBL_NETNS_MODE=sudo when user namespaces are blocked: `sudo unshare -n`
# still keeps nftables isolated from the host network namespace.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$REPO/bin/nft-blocklist"
FEEDSRV="$REPO/bin/feedserver"

# --- self-contain inside a user+net namespace -------------------------------
if [ -z "${NFTBL_IN_NS:-}" ]; then
  [ -x "$BIN" ] || { echo "build first: make build" >&2; exit 1; }
  go build -o "$FEEDSRV" "$REPO/test/e2e/feedserver" 2>/dev/null \
    || [ -x "$FEEDSRV" ] || { echo "cannot build feedserver (need go or prebuilt bin/feedserver)" >&2; exit 1; }
  case "${NFTBL_NETNS_MODE:-user}" in
    user)
      exec unshare -r -n env NFTBL_IN_NS=1 "$0" "$@"
      ;;
    sudo)
      command -v sudo >/dev/null 2>&1 || { echo "sudo netns mode requested, but sudo is unavailable" >&2; exit 1; }
      exec sudo -n unshare -n env NFTBL_IN_NS=1 "$0" "$@"
      ;;
    *)
      echo "unknown NFTBL_NETNS_MODE=${NFTBL_NETNS_MODE}; use user or sudo" >&2
      exit 1
      ;;
  esac
fi

ip link set lo up

WORK="$(mktemp -d)"
FIXDIR="$WORK/feeds"
cp -r "$REPO/test/fixtures/feeds" "$FIXDIR"
trap 'rm -rf "$WORK"' EXIT

# --- start the hermetic feed server ------------------------------------------
"$FEEDSRV" -addr 127.0.0.1:18080 -dir "$FIXDIR" > "$WORK/feedsrv.log" &
for _ in $(seq 1 50); do
  grep -q READY "$WORK/feedsrv.log" 2>/dev/null && break
  sleep 0.1
done
grep -q READY "$WORK/feedsrv.log" || { echo "feedserver did not start" >&2; exit 1; }

# --- test scaffolding ---------------------------------------------------------
PASS=0; FAIL=0
check() { # check <description> <command...>
  local desc="$1"; shift
  if "$@" > /dev/null 2>&1; then
    echo "ok       $desc"; PASS=$((PASS+1))
  else
    echo "FAIL     $desc"; FAIL=$((FAIL+1))
  fi
}
set_count() { # set_count <set>
  nft -j list set inet blocklist "$1" | grep -o '"elem"' | wc -l > /dev/null
  nft list set inet blocklist "$1" | sed -n 's/.*elements = {\(.*\)}.*/\1/p' | tr ',' '\n' | grep -c . || true
}

cat > "$WORK/allowlist.txt" <<EOF
# 9.10.11.12 appears in plain-ipv4.txt; it must never be blocked
9.10.11.12
EOF

cat > "$WORK/config.yaml" <<EOF
state_dir: $WORK/state
cache_dir: $WORK/cache
allowlist_file: $WORK/allowlist.txt
shrink_guard_percent: 50
policy:
  log_tcp_ports: [80, 443]
  log_udp_ports: [53]
feeds:
  - name: plain
    url: http://127.0.0.1:18080/plain-ipv4.txt
    format: plain
    min_fetch_interval: 0s
  - name: cidr
    url: http://127.0.0.1:18080/cidr-mixed.txt
    format: cidr
    family: both
    min_fetch_interval: 0s
EOF

CFG=(--config "$WORK/config.yaml")

# --- 1. validate + first apply -------------------------------------------------
check "validate accepts config"          "$BIN" "${CFG[@]}" validate
check "update applies against kernel"    "$BIN" "${CFG[@]}" update

check "table exists"                     nft list table inet blocklist
# nft prints -150 by its symbolic name "mangle"
check "chain hooked at input"            sh -c "nft list chain inet blocklist input | grep -q 'hook input priority mangle'"
check "static4 populated"                sh -c "nft list set inet blocklist static4 | grep -q '23.94.24.0/24'"
check "static6 populated"                sh -c "nft list set inet blocklist static6 | grep -q '2600:1234::/32'"
check "allowlisted ip in allow4"         sh -c "nft list set inet blocklist allow4 | grep -q '9.10.11.12'"
check "allowlisted ip NOT in static4"    sh -c "! nft list set inet blocklist static4 | grep -q '9.10.11.12'"
check "audit log rule present"           sh -c "nft list chain inet blocklist input | grep -q 'limit rate 5/minute'"

# --- 2. idempotent re-apply (no duplicate rules) -------------------------------
"$BIN" "${CFG[@]}" update > /dev/null 2>&1
RULES=$(nft list chain inet blocklist input | grep -c 'saddr' || true)
check "re-apply keeps rule count stable ($RULES)" test "$RULES" -le 10

# --- 3. dynamic set survives a feed update -------------------------------------
nft add element inet blocklist dynamic4 '{ 203.0.114.99 }'
"$BIN" "${CFG[@]}" update > /dev/null 2>&1
check "fail2ban-style dynamic entry survives update" \
  sh -c "nft list set inet blocklist dynamic4 | grep -q '203.0.114.99'"

# --- 4. shrink guard refuses a collapsed feed, --force overrides ---------------
printf '1.2.3.4\n' > "$FIXDIR/plain-ipv4.txt"
printf '# empty\n'  > "$FIXDIR/cidr-mixed.txt"
check "shrink guard refuses collapse"    sh -c "! $BIN ${CFG[*]} update"
check "kernel still has old entries"     sh -c "nft list set inet blocklist static4 | grep -q '23.94.24.0/24'"
check "--force applies collapse"         "$BIN" "${CFG[@]}" update --force
check "collapse actually applied"        sh -c "! nft list set inet blocklist static4 | grep -q '23.94.24.0/24'"

# --- 5. rollback re-applies last-known-good ------------------------------------
check "rollback succeeds"                "$BIN" "${CFG[@]}" rollback
check "rollback restored entries"        sh -c "nft list set inet blocklist static4 | grep -q '1.2.3.4'"

# --- 6. dry run changes nothing -------------------------------------------------
nft flush set inet blocklist static4
check "dry-run runs"                     sh -c "$BIN ${CFG[*]} update --force --dry-run | grep -q 'add element'"
check "dry-run did not repopulate"       sh -c "! nft list set inet blocklist static4 | grep -q '1.2.3.4'"

# --- 7. status works against live kernel ---------------------------------------
check "status reports kernel sets"       sh -c "$BIN ${CFG[*]} status | grep -q 'kernel set'"

echo
echo "integration: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
