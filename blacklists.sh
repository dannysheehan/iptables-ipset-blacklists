#!/bin/bash
#---------------------------------------------------------------------------
# @(#)$Id$
#title          :blacklists.sh
#description    :Script that uses iptables ipset to block ip's in known blacklists.
#author         :Danny W Sheehan
#date           :July 2014
#website        :www.ftmon.org  www.setuptips.com
#---------------------------------------------------------------------------
BL_AGE="23 hours ago"
BL_DIR="/var/lib/blacklists"


# goodinbadnets 
goodinbadnets () {
  myips=""
  for good in `ipset list good_ips | egrep -E "^[1-9]"`
  do
   myip=`ipset test bad_nets_n $good 2>&1 | grep "is in" | awk '{print $1}'`
   if [[ -n $myip ]];then
     myips="$myips $myip"
   fi
  done
  echo $myips
}

#blaclkist <ip/cdr> <listname>
blacklistit () {
 IP=$1
 LISTNAME=$2
 if echo "$IP" | egrep -q "\/[0-9]+"; then
   ipset add bad_nets_n $IP -exist
   badip=`goodinbadnets`
   if [[ -n "$badip" ]] ; then
     echo "*** Your IP $badip has been blacklisted in $LISTNAME" >&2
     ipset del bad_nets_n $IP
   fi
        
 else
   if ipset test good_ips $IP 2> /dev/null; then
     echo "*** Your IP $IP has been blacklisted in $LISTNAME" >&2
   else 
     ipset add bad_ips_n $IP -exist
   fi
 fi
}

# loadblacklist <name> <url>
loadblacklist () {
  BL_NAME=$1
  BL_URL=$2

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [[ ! -f "$BL_FILE" || \
       $(date +%s -r $BL_FILE) -lt $(date +%s --date="$BL_AGE") ]]
  then
    echo "-- getting fresh $BL_NAME from $BL_URL" >&2
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [[ -f $BL_FILE ]]; then
    echo "-- loading $BL_NAME from $BL_FILE" >&2
    # strip comments - mac address and ipv6 not support so strip :
    for ip in `grep -Ev "^#|^ *$|:" $BL_FILE | sed -e "s/[^0-9\.\/]//g" | grep -E "^[0-9]"`; do

      blacklistit $ip $BL_NAME
    done
  fi
}


mkdir -p $BL_DIR

if ! which ipset > /dev/null 2>&1;then
  echo "ERROR: You must install 'ipset'" >&2
  exit 1
fi


echo "ftmon.org blacklister -"  >&2
echo >&2


# Create temporary swap ipsets
ipset create bad_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
ipset flush bad_ips_n

ipset create bad_nets_n hash:net hashsize 4096 maxelem 262144 2> /dev/null
ipset flush bad_nets_n

#
# Setup the production ipsets if they don't yet exist.
#
if ! ipset list bad_ips > /dev/null 2>&1
then
  echo "-- creating bad_ips ipset as does not exist." >&2
  ipset create bad_ips hash:ip hashsize 4096 maxelem 262144
  if [[ -f "$BL_DIR/bad_ips.sav" ]]
  then
    echo "-- importing from save file $BL_DIR/bad_ips.sav" >&2
    grep -v "create" $BL_DIR/bad_ips.sav | ipset restore 
  fi
fi

if ! ipset list bad_nets > /dev/null 2>&1
then
  echo "-- creating bad_nets ipset as does not exist." >&2
  ipset create bad_nets hash:net hashsize 4096 maxelem 262144
  if [[ -f "$BL_DIR/bad_nets.sav" ]]
  then
    echo "-- importing from save file $BL_DIR/bad_nets.sav" >&2
    grep -v "create" $BL_DIR/bad_nets.sav | ipset restore 
  fi
fi

#
# Setup our firewall ip chains 
#
if ! iptables -L ftmon-blacklists -n > /dev/null 2>&1; then

  echo "-- creating iptables rules for first time" >&2
  iptables -N ftmon-blacklists

  iptables -I INPUT  \
       -m set --match-set bad_ips src -j ftmon-blacklists

  # insert the smaller set first.
  iptables -I INPUT \
       -m set --match-set bad_nets src -j ftmon-blacklists

  # keep a record of our business traffic ports.
  # so we can check if we blocked legitimate traffic if need be.
  iptables -A ftmon-blacklists -p tcp -m multiport --dports 80,443 \
         -m limit --limit 5/min \
         -j LOG --log-prefix "[BL DROP] "
  iptables -A ftmon-blacklists -p udp -m multiport --dport 53 \
         -m limit --limit 5/min \
         -j LOG --log-prefix "[BL DROP] "
  iptables -A ftmon-blacklists -m state --state NEW \
       -p tcp -m multiport --dports 80,443 -j REJECT 
  iptables -A ftmon-blacklists -m state --state NEW \
       -p udp -m multiport --dports 53 -j REJECT 
  iptables -A ftmon-blacklists -m state --state NEW -j DROP 
fi




#List of ips to whitelist
if ! ipset list good_ips > /dev/null 2>&1; then
  ipset create good_ips hash:ip
fi

# load fresh list each time as the list should be small.
ipset flush good_ips

# load your good ip's
WL_CUSTOM="$BL_DIR/whitelist.txt"
if [[ -f "$WL_CUSTOM" ]]; then
  for ip in `grep -Ev "^#|^ *$" $WL_CUSTOM | sed -e "s/#.*$//" -e "s/[^.0-9\/]//g"`; do
     ipset add good_ips $ip -exist
  done
fi
echo "-- loaded `ipset list good_ips | egrep "^[1-9]"  | wc -l` entries from whitelist " >&2

# load your personal custom blacklists.
BL_CUSTOM="$BL_DIR/blacklist.txt"
if [[ -f "$BL_CUSTOM" ]]; then
  for ip in `grep -Ev "^#|^ *$" $BL_CUSTOM | sed -e "s/#.*$//" -e "s/[^.0-9\/]//g"`; do
    blacklistit $ip $BLACKLIST
  done
fi

#
# Load Standard format blacklists
#

loadblacklist \
  "lists-blocklist-de-all" \
  "http://lists.blocklist.de/lists/all.txt"

# http://ipsec.pl/files/ipsec/blacklist-ip.txt
loadblacklist \
   "ipsec-pl" \
   "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt"


# http://www.infiltrated.net/blacklisted
loadblacklist \
   "infiltrated.net" \
   "http://www.infiltrated.net/blacklisted"

# Obtain List from openbl.org
#http://www.openbl.org/lists.html
loadblacklist \
  "openbl-org-base" \
  "http://www.openbl.org/lists/base.txt"


#
# bot nets
#
# https://palevotracker.abuse.ch/blocklists.php
loadblacklist \
  "palevotracker-abuse-ch" \
  "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist"

# https://spyeyetracker.abuse.ch/blocklist.php
loadblacklist \
  "spyeyetracker-abuse-ch" \
  "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist"

# https://zeustracker.abuse.ch/blocklist.php
loadblacklist \
  "zeustracker-abuse-ch-badips" \
  "https://zeustracker.abuse.ch/blocklist.php?download=badips"


#
# special cases, custom formats
#

# Obtain List of badguys from dshield.org
# https://isc.sans.edu/feeds_doc.html
  BL_NAME="dshield.org-top-10-2"
  BL_URL="http://feeds.dshield.org/top10-2.txt"

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [[ ! -f "$BL_FILE" || \
       $(date +%s -r $BL_FILE) -lt $(date +%s --date="$BL_AGE") ]]
  then
    echo "-- getting fresh $BL_NAME from $BL_URL" >&2
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [[ -f $BL_FILE ]]; then
    echo "-- loading $BL_NAME from $BL_FILE" >&2
    for ip in `grep -E "^[1-9]" $BL_FILE | cut -f1`; do
      blacklistit $ip $BL_NAME
    done
  fi


## Obtain List of badguys from dshield.org
  BL_NAME="dshield.org-block"
  BL_URL="http://feeds.dshield.org/block.txt"

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [[ ! -f "$BL_FILE" || \
       $(date +%s -r $BL_FILE) -lt $(date +%s --date="$BL_AGE") ]]
  then
    echo "-- getting fresh $BL_NAME from $BL_URL" >&2
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [[ -f $BL_FILE ]]; then
    echo "-- loading $BL_NAME from $BL_FILE" >&2
    for ip in `grep -E "^[1-9]" $BL_FILE | awk '{printf "%s/%s\n",$1,$3}'`; do
      blacklistit $ip $BL_NAME
    done
  fi

## Obtain List of badguys from spamhaus.org
## http://www.spamhaus.org/faq/section/DROP%20FAQ
  BL_NAME="spamhaus-org-lasso"
  BL_URL="http://www.spamhaus.org/drop/drop.lasso"

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [[ ! -f "$BL_FILE" || \
       $(date +%s -r $BL_FILE) -lt $(date +%s --date="$BL_AGE") ]]
  then
    echo "-- getting fresh $BL_NAME from $BL_URL" >&2
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [[ -f $BL_FILE ]]; then
    echo "-- loading $BL_NAME from $BL_FILE" >&2
    for ip in `grep -E "^[1-9]" $BL_FILE | cut -d\; -f1`; do
      blacklistit $ip $BL_NAME
    done
  fi


# swap in the new sets.
ipset swap bad_ips_n bad_ips
ipset swap bad_nets_n bad_nets

# show before and after counts.
echo "-- previous `ipset --list bad_ips_n | egrep "^[1-9]" | wc -l` bad_ips" >&2
echo "-- loaded `ipset --list bad_ips  | egrep "^[1-9]" | wc -l` bad_ips" >&2

echo >&2
echo "-- loaded `ipset --list bad_nets | egrep "^[1-9]" | wc -l` bad_nets" >&2
echo "-- previous `ipset --list bad_nets_n | egrep "^[1-9]" | wc -l` bad_nets" >&2


# save memory space by destroying the temporary swap ipset
ipset destroy bad_ips_n
ipset destroy bad_nets_n


# save our ipsets for quick import on reboot.
ipset save bad_ips  > $BL_DIR/bad_ips.sav
ipset save bad_nets > $BL_DIR/bad_nets.sav
