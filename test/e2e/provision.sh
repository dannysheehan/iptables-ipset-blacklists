#!/bin/sh
# Prepares a matrix VM: installs the locally built package with the
# distro's own package manager (this is itself part of the test — the
# .deb/.rpm must install cleanly everywhere).
set -eu

if command -v apt-get > /dev/null 2>&1; then
  apt-get update -q
  apt-get install -y /repo/dist/nft-blocklist_*.deb
elif command -v dnf > /dev/null 2>&1; then
  dnf install -y /repo/dist/nft-blocklist-*.rpm
elif command -v zypper > /dev/null 2>&1; then
  zypper --non-interactive --no-gpg-checks install --allow-unsigned-rpm /repo/dist/nft-blocklist-*.rpm
else
  echo "no supported package manager" >&2
  exit 1
fi

nft-blocklist version
