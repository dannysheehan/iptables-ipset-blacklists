#!/bin/sh
# Post-install: register units but do NOT enable/start them — an admin must
# review /etc/nft-blocklist/config.yaml (especially the allowlist) before a
# tool that drops traffic goes live. Auto-starting a firewall tool that the
# operator hasn't configured is how people lock themselves out.
set -e

if command -v systemctl > /dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<'EOF'
nft-blocklist installed.

Next steps:
  1. review /etc/nft-blocklist/config.yaml and feeds.d/
  2. add YOUR management IPs to /etc/nft-blocklist/allowlist.txt
  3. dry run:            nft-blocklist update --dry-run | less
  4. enable:             systemctl enable --now nft-blocklist.timer
     boot protection:    systemctl enable nft-blocklist-restore.service
  5. verify:             nft-blocklist status
EOF
