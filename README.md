iptables-ipset-blacklists
=========================

There are lots of tools and services that do a good job of identifying abusers, spammers and 
hackers. They provide lists of bad IPs in blacklists. By blocking these bad IPs from
accessing your websites and servers you can go a long way to protecting them and also
preventing a lot of useless traffic being logged in your logs. It also helps prevent
a lot of noise so that your snort, ossec, logwatcher, mod-security, psad etc. tools can
do some real work of finding legitimate and directed attacks to your servers.


## Requires

 - iptables
 - ipset

## Installation
 
- setup your whitelist and blacklist
    -  /var/lib/blacklists/{whitelist.txt,blacklist.txt}
- run _sudo blacklists.sh_  
- setup your _/etc/crontab_
~~~
@reboot         root    /usr/local/bin/blacklists.sh
@daily          root    /usr/local/bin/blacklists.sh
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

- loads known authorative blacklists and allows you add/configure others easily 
- allows you to create your own blacklist of IPs and net ranges.
- allows you to create a whitelist and notifies you if one of your whitelisted IPs
is in a blacklist. Don't block legitimate traffic.
- supports network range blacklists as well as ip based blacklists.
- automatically adds dedicated/separate iptables chain for blacklisting (tested on Ubuntu UFW only).
It sets up the firewall rules for you.
- logs access to customer facing ports such as http/https/domain with rate limiting so you can 
go back to check your logs in case you are blocking real users/customers. All other 
ports are blocked without logging.
- keeps cache of downloaded blacklists, so it only downloads a blacklist once in 24 hour period. 
This prevents blacklist providers banning your IP for downloading too often.
- uses a temporary ipset when loading updated blacklists to ensure you are always protected 
during blacklist updates.



## References and Other blacklist scripts

[blacklist script](http://sysadminnotebook.blogspot.com.au/2013_07_01_archive.html)

[ipset-blacklist](https://github.com/trick77/ipset-blacklist/)

[ipsets](http://kirkkosinski.com/2013/11/mass-blocking-evil-ip-addresses-iptables-ip-sets/)

