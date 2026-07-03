#!/usr/bin/env bash
# Drives the Vagrant e2e matrix: up -> phase1 -> reboot -> phase2 -> destroy.
# Usage: test/e2e/run.sh [box|all]   (boxes: ubuntu2404 debian12 rocky9 leap156 fedora)
# KEEP=1 leaves VMs running for inspection.
set -euo pipefail

cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
TARGET="${1:-all}"

# Pick cloud-image boxes for libvirt, bento for VirtualBox. vagrant-libvirt
# is the usual backend on Linux hosts without VirtualBox.
if [ -z "${VAGRANT_DEFAULT_PROVIDER:-}" ]; then
  if [ "$(uname -s)" = Linux ] && ! command -v VBoxManage >/dev/null 2>&1; then
    export VAGRANT_DEFAULT_PROVIDER=libvirt
  fi
fi

BOXES=(ubuntu2404 debian12 rocky9 leap156 fedora)
[ "$TARGET" = all ] || BOXES=("$TARGET")

# The VM runs the feedserver itself, so it needs a linux/amd64 build
# regardless of the host platform.
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/feedserver-linux ./test/e2e/feedserver)
if ! compgen -G "$REPO/dist/nft-blocklist_*.deb" > /dev/null; then
  echo "run 'make package' first" >&2
  exit 1
fi

overall=0
for box in "${BOXES[@]}"; do
  echo "=== $box ==================================================="
  vagrant up "$box"
  # rsync synced folders need an explicit push after package rebuilds.
  vagrant rsync "$box"
  if vagrant ssh "$box" -c "sudo bash /repo/test/e2e/vm-test.sh phase1" \
     && vagrant reload "$box" \
     && vagrant ssh "$box" -c "sudo bash /repo/test/e2e/vm-test.sh phase2"; then
    echo "=== $box PASSED"
  else
    echo "=== $box FAILED"
    overall=1
  fi
  [ "${KEEP:-0}" = 1 ] || vagrant destroy -f "$box"
done
exit $overall
