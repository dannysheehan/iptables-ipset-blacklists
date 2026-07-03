#!/usr/bin/env bash
# In-VM e2e assertions, run as root via `vagrant ssh -c`. Two phases so
# run.sh can reboot the VM between them:
#   vm-test.sh phase1   install-time checks, first update, enable units
#   vm-test.sh phase2   post-reboot checks (boot restore + timer)
set -euo pipefail

PHASE="${1:?usage: vm-test.sh phase1|phase2}"
PASS=0; FAIL=0
check() {
  local desc="$1"; shift
  if "$@" > /dev/null 2>&1; then
    echo "ok       $desc"; PASS=$((PASS+1))
  else
    echo "FAIL     $desc"; FAIL=$((FAIL+1))
  fi
}
finish() {
  echo "e2e($PHASE): $PASS passed, $FAIL failed"
  [ "$FAIL" -eq 0 ]
}

if [ "$PHASE" = phase1 ]; then
  # Hermetic feeds: serve the repo fixtures from inside the VM. Tests must
  # not hit live providers (rate limits, changing content, offline CI).
  pkill -f feedserver 2>/dev/null || true
  nohup /repo/bin/feedserver-linux -addr 127.0.0.1:18080 -dir /repo/test/fixtures/feeds \
    > /tmp/feedserver.log 2>&1 &
  for _ in $(seq 1 50); do grep -q READY /tmp/feedserver.log 2>/dev/null && break; sleep 0.1; done

  # Point the packaged config at the local fixtures (keeping the packaged
  # feeds.d out of the way — those URLs are live providers).
  mkdir -p /etc/nft-blocklist/feeds.d.disabled
  mv /etc/nft-blocklist/feeds.d/*.yaml /etc/nft-blocklist/feeds.d.disabled/ 2>/dev/null || true
  cat > /etc/nft-blocklist/feeds.d/e2e.yaml <<'EOF'
feeds:
  - name: e2e-plain
    url: http://127.0.0.1:18080/plain-ipv4.txt
    format: plain
    min_fetch_interval: 0s
  - name: e2e-cidr
    url: http://127.0.0.1:18080/cidr-mixed.txt
    format: cidr
    family: both
    min_fetch_interval: 0s
EOF
  echo "9.10.11.12" > /etc/nft-blocklist/allowlist.txt

  check "validate config"              nft-blocklist validate
  check "first update applies"         nft-blocklist update
  check "table exists"                 nft list table inet blocklist
  check "static4 has feed entry"       sh -c "nft list set inet blocklist static4 | grep -q '23.94.24.0/24'"
  check "allowlisted ip protected"     sh -c "nft list set inet blocklist allow4 | grep -q '9.10.11.12'"
  check "status runs"                  nft-blocklist status

  # fail2ban-style dynamic entry must survive a second update.
  nft add element inet blocklist dynamic4 '{ 203.0.114.99 timeout 1h }'
  check "second update"                nft-blocklist update
  check "dynamic entry survived"       sh -c "nft list set inet blocklist dynamic4 | grep -q '203.0.114.99'"

  check "enable timer"                 systemctl enable --now nft-blocklist.timer
  check "timer scheduled"              sh -c "systemctl list-timers | grep -q nft-blocklist"
  check "enable boot restore"          systemctl enable nft-blocklist-restore.service

  # Coexistence: the distro firewall (if active) and our table both live.
  if systemctl is-active firewalld > /dev/null 2>&1; then
    check "firewalld coexists"         sh -c "firewall-cmd --state && nft list table inet blocklist"
  fi
  finish
fi

if [ "$PHASE" = phase2 ]; then
  # After reboot: the restore service must have re-applied the ruleset
  # BEFORE feeds could possibly re-download (feedserver is not running).
  check "restore service ran"          sh -c "systemctl is-active nft-blocklist-restore.service | grep -qE 'active|exited'"
  check "table restored at boot"       nft list table inet blocklist
  check "static entries restored"      sh -c "nft list set inet blocklist static4 | grep -q '23.94.24.0/24'"
  check "timer still scheduled"        sh -c "systemctl list-timers | grep -q nft-blocklist"
  check "journal has run logs"         sh -c "journalctl -u nft-blocklist-restore.service --no-pager | grep -qi 'ruleset'"
  finish
fi
