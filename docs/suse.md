# SLES / openSUSE

Tested on openSUSE Leap 15.6 (e2e matrix box `leap156`), which tracks
SLES 15. SLES 15+ ships firewalld (nftables backend) by default and
deprecates SuSEfirewall2/iptables.

## Install

```sh
sudo zypper install ./nft-blocklist-*.x86_64.rpm
sudo vi /etc/nft-blocklist/allowlist.txt          # ADD YOUR OWN IPs FIRST
sudo nft-blocklist update --dry-run | less
sudo nft-blocklist update
sudo systemctl enable --now nft-blocklist.timer
sudo systemctl enable nft-blocklist-restore.service
```

## Coexistence with firewalld / YaST

Same model as the RHEL family (see [rhel-family.md](rhel-family.md)):
firewalld and YaST's firewall module keep managing zones and services;
nft-blocklist owns an independent `table inet blocklist` at an earlier
hook priority. Neither reload path affects the other.
