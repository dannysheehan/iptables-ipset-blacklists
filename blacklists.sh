#!/bin/bash
#---------------------------------------------------------------------------
# @(#)$Id$
#title          :blacklists.sh
#description    :Uses iptables ipset to block ip's in known blacklists.
#author         :Danny W Sheehan
#date           :July 2014
#website        :www.ftmon.org  www.setuptips.com
#---------------------------------------------------------------------------

#
# Where we keep all the blacklists.
BL_DIR="/var/lib/blacklists"
mkdir -p $BL_DIR

# Some hosting services such as RamNode will ban you for using > 90% of the cpu!!!
# So we recommend installing cpulimit and limiting to 20% of cpu usage when 
# calling this script.
#
## cpulimit -z -l 20 /usr/local/bin/blacklists.sh
# cpulimit dosn't like scripts writing to stdout/stderr so them redirect to 
# an output file.
#
exec > $BL_DIR/blacklists.out 2>&1

SCRIPT_NAME=$0
HOST_NAME=`uname -n`

# default syslog messages priority and tag.
LOG_PRI="local0.notice"
LOG_TAG="[$SCRIPT_NAME]"

# Set to empty string if you don't want error emails. Otherwise, set to an admin email.
MAIL_ADMIN="root"

# Logging is enabled for the following ports this is so we can do later audit checks
# in case we are droping legitimate traffic.
TCP_PORTS="53,80,443"
UDP_PORTS="53"

# If PSAD is installed then block Danger Level = $DL and above attackers
# each time the blacklists are reloaded.
DL=3

# Retrieve new blacklists only when they are older then BL_AGE
BL_AGE="23 hours ago"

#---------------------------------------------------------------------------

# logmessage <msg_text>
logmessage () {
  MSG="$1"
  logger -s -p $LOG_PRI -t $LOG_TAG "$MSG"
}

# <ips> goodinbadnets
# - returns whitelist <ips> that that are in blacklists.
goodinbadnets () {
  myips=""
  for good in `ipset list good_ips | egrep -E "^[1-9]"`
  do
   myip=`ipset test bad_nets_n $good 2>&1 | grep "is in" | awk '{print $1}'`
   if [ -n "$myip" ];then
     myips="$myips $myip"
   fi
  done
  echo $myips
}

# blacklistit <ip/cdr> <listname>
#  - blacklists the given <ip/cdr> to bad_nets_n or gad_ips_n
#  - also checks if the <ip/cdr> blacklists one of your whitelisted ips, and 
#  if so it will remove it from the blacklist and warn you.
blacklistit () {
 IP=$1
 LISTNAME=$2
 if echo "$IP" | egrep -q "\/[0-9]+"; then
   ipset add bad_nets_n $IP -exist
   badip=`goodinbadnets`
   if [ -n "$badip" ]; then
     error_msg="ERROR Your whitelist IP $badip has been blacklisted in $LISTNAME"
     logmessage "$error_msg"
     ERROR_MSGS="$ERROR_MSGS\n$error_msg"
     ipset del bad_nets_n $IP
   fi
        
 else
   if ipset test good_ips $IP 2> /dev/null; then
     error_msg="ERROR Your whitelist IP $IP has been blacklisted in $LISTNAME"
     logmessage "$error_msg"
     ERROR_MSGS="$ERROR_MSGS\n$error_msg"
   else 
     ipset add bad_ips_n $IP -exist
   fi
 fi
}

# loadblacklist <name> <url>
# - loads standard form blacklist from <url> website, labels cache files with <name>
loadblacklist () {
  BL_NAME=$1
  BL_URL=$2

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [ ! -f "$BL_FILE" ] || [ $(date +%s -r "$BL_FILE") -lt $(date +%s --date="$BL_AGE") ]; then
    echo "-- getting fresh $BL_NAME from $BL_URL"
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [ -f "$BL_FILE" ]; then
    echo "-- loading $BL_NAME from $BL_FILE"

    # strip comments - mac address and ipv6 not supported yet so strip :
    awk '{print $1}' $BL_FILE | cut -d\; -f1 | cut -d\, -f1 | grep -Ev "^#|^ *$|:" | sed -e "s/[^0-9\.\/]//g" | grep -E "^[0-9]" > ${BL_FILE}.filtered
    echo "-- loading $BL_NAME - `wc -l ${BL_FILE}.filtered` entries"

    for ip in `cat ${BL_FILE}.filtered`; do
      blacklistit $ip $BL_NAME
    done
  fi
}

#---------------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------------

# concatenated list of all error message
ERROR_MSGS=""


if ! which ipset > /dev/null 2>&1;then
  echo "ERROR: You must install 'ipset'"
  exit 1
fi


logmessage "ftmon.org blacklist script started"


# Create temporary swap ipsets
ipset create bad_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
ipset flush bad_ips_n

ipset create bad_nets_n hash:net hashsize 4096 maxelem 262144 2> /dev/null
ipset flush bad_nets_n

#
# Setup the active ipsets if they don't yet exist.
# Load them from last save sets to speed up load times in cases of reboot
# and ensure protection faster.
#
if ! ipset list bad_ips > /dev/null 2>&1
then
  echo "-- creating bad_ips ipset as does not exist."
  ipset create bad_ips hash:ip hashsize 4096 maxelem 262144
  if [ -f "$BL_DIR/bad_ips.sav" ]; then
    echo "-- importing from save file $BL_DIR/bad_ips.sav"
    grep -v "create" $BL_DIR/bad_ips.sav | ipset restore 
  fi
fi

if ! ipset list bad_nets > /dev/null 2>&1
then
  echo "-- creating bad_nets ipset as does not exist."
  ipset create bad_nets hash:net hashsize 4096 maxelem 262144
  if [ -f "$BL_DIR/bad_nets.sav" ]; then
    echo "-- importing from save file $BL_DIR/bad_nets.sav"
    grep -v "create" $BL_DIR/bad_nets.sav | ipset restore 
  fi
fi

#
# Setup our firewall ip chains 
#
if ! iptables -L ftmon-blacklists -n > /dev/null 2>&1; then

  echo "-- creating iptables rules for first time"
  iptables -N ftmon-blacklists

  iptables -I INPUT  \
       -m set --match-set bad_ips src -j ftmon-blacklists

  # insert the smaller set first.
  iptables -I INPUT \
       -m set --match-set bad_nets src -j ftmon-blacklists

  # keep a record of our business traffic ports.
  # so we can check if we blocked legitimate traffic if need be.
  # DNS and http/https are most typical legit ports
  iptables -A ftmon-blacklists -p tcp -m multiport --dports $TCP_PORTS \
         -m limit --limit 5/min \
         -j LOG --log-prefix "[BL DROP] "
  iptables -A ftmon-blacklists -p udp -m multiport --dport $UDP_PORTS \
         -m limit --limit 5/min \
         -j LOG --log-prefix "[BL DROP] "
  iptables -A ftmon-blacklists -m state --state NEW \
       -p tcp -m multiport --dports $TCP_PORTS -j REJECT 
  iptables -A ftmon-blacklists -m state --state NEW \
       -p udp -m multiport --dports $UDP_PORTS -j REJECT 
  iptables -A ftmon-blacklists -m state --state NEW -j DROP 
fi


# List of ips to whitelist
if ! ipset list good_ips > /dev/null 2>&1; then
  ipset create good_ips hash:ip
fi

# load fresh white list each time as the list should be small.
ipset flush good_ips

# load your good ip's
WL_CUSTOM="$BL_DIR/whitelist.txt"
count=0
if [ -f "$WL_CUSTOM" ]; then
  for ip in `grep -Ev "^#|^ *$" $WL_CUSTOM | sed -e "s/#.*$//" -e "s/[^.0-9\/]//g"`; do
     ipset add good_ips $ip -exist
     count=$((count+1))
  done
fi
echo "-- loaded $count entries from $WL_CUSTOM"

# load your personal custom blacklists.
BL_CUSTOM="$BL_DIR/blacklist.txt"
count=0
if [ -f "$BL_CUSTOM" ]; then
  for ip in `grep -Ev "^#|^ *$" $BL_CUSTOM | sed -e "s/#.*$//" -e "s/[^.0-9\/]//g"`; do
    blacklistit $ip $BLACKLIST
    count=$((count+1))
  done
fi
echo "-- loaded `ipset list bad_ips_n | egrep "^[1-9]"  | wc -l` entries from blacklist "
echo "-- loaded $count entries from $BL_CUSTOM"

# If PSAD is installed then use some of it's good detection work
# to stop attackers.
count=0
if [ -f "/var/log/psad/top_attackers" ]; then
 for ip in `awk '{print $2, $1}' /var/log/psad/top_attackers | grep "^[$DL-]" | awk '{print $2}'`; do
    blacklistit $ip $BLACKLIST
    count=$((count+1))
  done
fi
echo "-- loaded $count entries from /var/log/psad/top_attackers "

#
# Load Standard format blacklists
# Some of them are over zealous, you may want to comment out.
#
loadblacklist \
  "lists-blocklist-de-all" \
  "http://lists.blocklist.de/lists/all.txt"

loadblacklist \
   "ipsec-pl" \
   "http://doc.emergingthreats.net/pub/Main/RussianBusinessNetwork/RussianBusinessNetworkIPs.txt"

loadblacklist \
   "infiltrated.net" \
   "http://www.infiltrated.net/blacklisted"

loadblacklist \
  "openbl-org-base" \
  "http://www.openbl.org/lists/base.txt"

loadblacklist \
      "ci-army-malcious" \
        "http://cinsscore.com/list/ci-badguys.txt"

loadblacklist \
      "autoshun-org" \
        "http://www.autoshun.org/files/shunlist.csv"

loadblacklist \
      "bruteforceblocker" \
        "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"

loadblacklist \
      "torexitnodes" \
        "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"

loadblacklist \
      "spamhaus-org-lasso" \
        "http://www.spamhaus.org/drop/drop.lasso"

loadblacklist \
      "dshield.org-top-10-2" \
        "http://feeds.dshield.org/top10-2.txt"

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
# special cases, custom formats blacklists
#

# Obtain List of badguys from dshield.org
# https://isc.sans.edu/feeds_doc.html
  BL_NAME="dshield.org-top-10-2"
  BL_URL="http://feeds.dshield.org/top10-2.txt"

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [ ! -f "$BL_FILE" ] || [ $(date +%s -r "$BL_FILE") -lt $(date +%s --date="$BL_AGE") ]; then
    echo "-- getting fresh $BL_NAME from $BL_URL"
    wget -q -t 2 --output-document=$BL_FILE $BL_URL
  fi
  
  if [ -f "$BL_FILE" ]; then
    echo "-- loading $BL_NAME from $BL_FILE"
    for ip in `grep -E "^[1-9]" $BL_FILE | cut -f1`; do
      blacklistit $ip $BL_NAME
    done
  fi



# swap in the new sets.
ipset swap bad_ips_n bad_ips
ipset swap bad_nets_n bad_nets

# show before and after counts.
complete_msg="bad_ips: current=`ipset --list bad_ips_n | egrep '^[1-9]' | wc -l` \
  previous=`ipset --list bad_ips  | egrep '^[1-9]' | wc -l` \
  bad_nets: previous=`ipset --list bad_nets | egrep '^[1-9]' | wc -l` \
  current=`ipset --list bad_nets_n | egrep '^[1-9]' | wc -l`"

logmessage "$complete_msg"

# only send email if problems.
if [ -n "$MAIL_ADMIN" ] && [ -n "$ERROR_MSGS" ]; then
  echo -e "${complete_msg}\n${ERROR_MSGS}" | mail -s "$LOG_TAG $HOST_NAME" $MAIL_ADMIN
fi


# save memory space by destroying the temporary swap ipset
ipset destroy bad_ips_n
ipset destroy bad_nets_n


# save our ipsets for quick import on reboot.
ipset save bad_ips  > $BL_DIR/bad_ips.sav
ipset save bad_nets > $BL_DIR/bad_nets.sav

logmessage "ftmon.org blacklist script completed"

