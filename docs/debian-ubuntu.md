# Ubuntu / Debian

Tested on Ubuntu 24.04 and Debian 12 (e2e matrix boxes `ubuntu2404`,
`debian12`).

## Install

```sh
sudo apt install ./nft-blocklist_*_amd64.deb
sudo editor /etc/nft-blocklist/allowlist.txt      # ADD YOUR OWN IPs FIRST
sudo nft-blocklist update --dry-run | less
sudo nft-blocklist update
sudo systemctl enable --now nft-blocklist.timer
sudo systemctl enable nft-blocklist-restore.service
```

## Coexistence with UFW

UFW and nft-blocklist do not interact: UFW manages its own chains, while
nft-blocklist owns a separate `table inet blocklist` whose input chain runs
at priority -150 — *before* UFW's filter chains (priority 0). Blocked
sources are dropped before UFW ever evaluates them, and UFW rules keep
working untouched. Nothing to configure.

Ubuntu's `iptables` command is nft-backed (`iptables-nft`); rules you see
in `iptables -L` and our table live in the same kernel framework without
conflict.

## Logs

```sh
journalctl -u nft-blocklist.service          # update runs
journalctl -k | grep '\[BL DROP\]'           # audit-logged drops (rate-limited)
```
