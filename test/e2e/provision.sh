#!/bin/sh
# Prepares a matrix VM: installs the locally built package with the
# distro's own package manager (this is itself part of the test — the
# .deb/.rpm must install cleanly everywhere).
set -eu

# dist/ may contain packages from prior builds (e.g. git-describe vs tag);
# install only the newest file so package managers never see two versions.
pick_newest() {
  # shellcheck disable=SC2012
  ls -t "$@" | head -n1
}

if command -v apt-get > /dev/null 2>&1; then
  apt-get update -q
  pkg=$(pick_newest /repo/dist/nft-blocklist_*.deb)
  apt-get install -y "$pkg"
elif command -v dnf > /dev/null 2>&1; then
  pkg=$(pick_newest /repo/dist/nft-blocklist-*.rpm)
  dnf install -y "$pkg"
elif command -v zypper > /dev/null 2>&1; then
  pkg=$(pick_newest /repo/dist/nft-blocklist-*.rpm)
  zypper --non-interactive --no-gpg-checks install --allow-unsigned-rpm "$pkg"
else
  echo "no supported package manager" >&2
  exit 1
fi

nft-blocklist version
