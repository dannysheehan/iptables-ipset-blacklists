# Migrating from blacklists.sh (v1)

The v1 Bash script (now frozen in `legacy/`) used iptables + ipset + cron.
v2 (`nft-blocklist`) replaces all three. The two stacks don't conflict —
they use different kernel frameworks — but running both wastes CPU and
confuses debugging, so migrate cleanly:

## 1. Install nft-blocklist and verify

```sh
apt install ./nft-blocklist_*.deb     # or: dnf/zypper install ./nft-blocklist-*.rpm
# copy your old whitelist across (same one-IP-per-line format):
cp /var/lib/blacklists/whitelist.txt /etc/nft-blocklist/allowlist.txt
cp /var/lib/blacklists/blacklist.txt /etc/nft-blocklist/blocklist.local   # if you had one
nft-blocklist update --dry-run | less   # review what would be applied
nft-blocklist update
nft-blocklist status
```

## 2. Remove the v1 pieces

```sh
# cron entries
sed -i '/blacklists.sh/d' /etc/crontab

# iptables chain and rules (v1 inserted two INPUT jumps)
iptables -D INPUT -m set --match-set bad_nets src -j ftmon-blacklists 2>/dev/null
iptables -D INPUT -m set --match-set bad_ips  src -j ftmon-blacklists 2>/dev/null
iptables -F ftmon-blacklists 2>/dev/null && iptables -X ftmon-blacklists 2>/dev/null

# ipsets and cache
ipset destroy bad_ips 2>/dev/null; ipset destroy bad_nets 2>/dev/null
ipset destroy good_ips 2>/dev/null
rm -rf /var/lib/blacklists
rm -f /usr/local/bin/blacklists.sh
```

## 3. Enable the schedule

```sh
systemctl enable --now nft-blocklist.timer
systemctl enable nft-blocklist-restore.service   # protection at boot
```

## What replaced what

| v1                                    | v2                                                    |
|---------------------------------------|-------------------------------------------------------|
| `bad_ips` / `bad_nets` ipsets          | `static4`/`static6` nftables sets (CIDR-merged)       |
| `good_ips` ipset + warning email       | `allow4`/`allow6` sets + `allowlist_collision` event  |
| `ftmon-blacklists` iptables chain      | `table inet blocklist` chain `input` (priority -150)  |
| cron `@daily` + `@reboot` + cpulimit   | systemd timer (jittered) + restore service + cgroups  |
| `.sav` files restored at boot          | `last-good.nft` applied before network-pre.target     |
| mail to root on problems               | notifications: webhook / command sinks (see docs)     |
| PSAD top_attackers import              | not carried over — use fail2ban integration instead   |

Most v1 feed URLs (openbl, autoshun, infiltrated.net, abuse.ch trackers)
are dead; the v2 defaults in `feeds.d/` are their maintained successors.
