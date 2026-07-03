#!/bin/sh
# Pre-remove: stop scheduled runs. The nftables table is deliberately left
# in place — removing a package should not instantly expose the host; the
# admin removes the table explicitly when ready:
#   nft delete table inet blocklist
set -e

if command -v systemctl > /dev/null 2>&1; then
  systemctl disable --now nft-blocklist.timer 2> /dev/null || true
  systemctl disable nft-blocklist-restore.service 2> /dev/null || true
fi
