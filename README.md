iptables-ipset-blacklists
=========================

There are lots of tools and services that do a good job of identifying abusers, spammers and
hackers. They provide lists of bad IPs in blacklists. By blocking these bad IPs from
accessing your websites and servers you can go a long way to protecting them and also
preventing a lot of useless traffic being logged in your logs. It also helps prevent
a lot of noise so that your snort, ossec, logwatcher, mod-security, psad etc. tools can
do some real work of finding legitimate and directed attacks to your servers.

NOTE: Some hosting companies will shutdown your VPS server if you use more than .9 load.
So we recommending using **cpulimit** to invoke blacklists.sh

`cpulimit -l 20 /usr/local/bin/blacklists.sh`

## Requires

 - iptables
 - ipset

## Installation

- setup your personal whitelist and blacklist (optional)
    -  /var/lib/blacklists/{whitelist.txt,blacklist.txt}
- run _sudo blacklists.sh_  
- setup your _/etc/crontab_

    ~~~
    @reboot         root    /usr/local/bin/blacklists.sh
    @daily          root    /usr/local/bin/blacklists.sh
    ~~~

- NOTE: If your hosting provider is Ramnode your terms of service prevent you from using all
your available CPU load.  So use cpulimit to restrict the CPU usage to 20%.
    ~~~
    @reboot         root    cpulimit -z -l 20 /usr/local/bin/blacklists.sh
    @daily          root    cpulimit -z -l 20 /usr/local/bin/blacklists.sh
    ~~~

- setup logging

_/etc/logrotate.d/blacklist_
~~~
/var/log/blacklists.log
{
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        invoke-rc.d rsyslog reload >/dev/null 2>&1 || true
    endscript
}
~~~

_/etc/rsyslog.d/30-blacklist.conf_
~~~
# Log kernel generated UFW log messages to file
:msg,contains,"[BL " /var/log/blacklists.log
& ~
~~~

## Features

- loads known authoritative blacklists and allows you to add/configure others easily
- allows you to create your own blacklist of IPs and net ranges.
- allows you to create a whitelist and notifies you if one of your whitelisted IPs
is in a blacklist. Don't block legitimate traffic.
- supports network range blacklists as well as ip based blacklists.
- automatically adds dedicated/separate iptables chain for blacklisting (tested on Ubuntu/Centos ).
It sets up the firewall rules for you.
- logs access to customer facing ports such as http/https/domain with rate limiting so you can
go back to check your logs in case you are blocking real users/customers. All other
ports are blocked without logging.
- keeps cache of downloaded blacklists, so it only downloads a blacklist once in 24 hour period.
This prevents blacklist providers banning your IP for downloading too often.
- uses a temporary ipset when loading updated blacklists to ensure you are always protected
during blacklist updates.
- after a reboot cached ipsets are loaded to ensure you are protected faster after an outage and not left exposed until the blacklists are re-imported.

## Example syslog messages

- everything is logged to syslog, for your monitoring to pick up issues.

~~~
Jan 14 14:51:32 serverx [/usr/local/bin/blacklists.sh]: ftmon.org blacklist script started
Jan 14 14:52:17 serverx [/usr/local/bin/blacklists.sh]: ERROR Your whitelist IP 54.235.163.229 has been blacklisted in lists-blocklist-de-all
Jan 14 14:57:47 serverx [/usr/local/bin/blacklists.sh]: ERROR Your whitelist IP 67.207.202.9 has been blacklisted in infiltrated.net
Jan 14 15:02:03 serverx [/usr/local/bin/blacklists.sh]: bad_ips: current=53435   previous=53435   bad_nets: previous=1535   current=1535
Jan 14 15:02:03 serverx [/usr/local/bin/blacklists.sh]: ftmon.org blacklist script completed
~~~

### Example email message

- optional feature to be emailed if there are issues.

~~~
From: root
Date: Wed, Jan 1, 2015 at 3:09 PM
Subject: [/usr/local/bin/blacklists.sh] sever.org
To: root


bad_ips: current=29294   previous=57196   bad_nets: previous=1536   current=1536

ERROR Your whitelist IP 192.0.81.17 has been blacklisted in lists-blocklist-de-all
ERROR Your whitelist IP 192.0.81.57 has been blacklisted in lists-blocklist-de-all
ERROR Your whitelist IP 67.207.202.9 has been blacklisted in infiltrated.net
~~~


### Firewall audit log of production ports

- only ports such as DNS,HTTP,HTTPS are logged, so you can
go back and do auditing in case legitimate traffic is being blocked.

_/var/log/blacklists.log_
~~~
Jan 1 19:24:42 server kernel: [541334.229673] [BL DROP] IN=eth0 OUT= MAC=d4:be:d9:a1:62:06:78:da:6e:25:cc:00:08:00 SRC=124.232.142.220 DST=x.x.x.x LEN=58 TOS=0x00 PREC=0x00 TTL=234 ID=54321 PROTO=UDP SPT=47479 DPT=53 LEN=38
~~~

### Firewall rules created

- this is the iptables chain that is automatically created based on `TCP_PORTS="53,80,443"`
and `UDP_PORTS="53"`
- production ports are rejected not droped so as not to "stir up" hackers.
- there is also rate limiting on production port logging.


~~~
iptables -L ftmon-blacklists
Chain ftmon-blacklists (2 references)
target     prot opt source               destination
LOG        tcp  --  anywhere             anywhere             multiport dports http,https limit: avg 5/min burst 5 LOG level warning prefix "[BL DROP] "
LOG        udp  --  anywhere             anywhere             multiport dports domain limit: avg 5/min burst 5 LOG level warning prefix "[BL DROP] "
REJECT     tcp  --  anywhere             anywhere             state NEW multiport dports http,https reject-with icmp-port-unreachable
REJECT     udp  --  anywhere             anywhere             state NEW multiport dports domain reject-with icmp-port-unreachable
DROP       all  --  anywhere             anywhere             state NEW

~~~

## References and Other blacklist scripts

[blacklist script](http://sysadminnotebook.blogspot.com.au/2013_07_01_archive.html)

[ipset-blacklist](https://github.com/trick77/ipset-blacklist/)

[ipsets](http://kirkkosinski.com/2013/11/mass-blocking-evil-ip-addresses-iptables-ip-sets/)


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/dannysheehan/iptables-ipset-blacklists/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

