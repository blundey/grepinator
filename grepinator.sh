#!/bin/bash 
#
# Grepinator v0.0.1-alpha
#
# Grepinator is a series of bash scripts utilising the power of grep and regex.
#
# See Readme.md for usage and instructions.


######################################################
# GLOBAL VARS (change as needed)
FILTERDIR=./filters/
IPSET_GREPINATOR="grepinator"
IPSET_GREPINATOR_TMP=${IPSET_GREPINATOR}-tmp
IPSET_BLACKLIST_NAME="grepinatorBL"
IPSET_TMP_BLACKLIST_NAME=${IPSET_BLACKLIST_NAME}-tmp
DB_NAME="grepinator"
DB_PATH="/var/log/grepinator"
MAXELEM=131072
TIMEOUT="10800" # 3 hours
BLACKLISTS=(
    "https://www.projecthoneypot.org/list_of_ips.php?t=d&rss=1" # Project Honey Pot Directory of Dictionary Attacker IPs
#   "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"  # TOR Exit Nodes
#    "http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
#    "https://www.spamhaus.org/drop/drop.lasso" # Spamhaus Don't Route Or Peer List (DROP)
#    "https://cinsscore.com/list/ci-badguys.txt" # C.I. Army Malicious IP List
#    "https://lists.blocklist.de/lists/all.txt" # blocklist.de attackers
#    "https://blocklist.greensnow.co/greensnow.txt" # GreenSnow
#   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" # Firehol Level 1
#   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/stopforumspam_7d.ipset" # Stopforumspam via Firehol
)
####################################################

banner () {
echo '
____ ____ ____ ___  _ _  _ ____ ___ ____ ____
| __ |__/ |___ |__] | |\ | |__|  |  |  | |__/
|__] |  \ |___ |    | | \| |  |  |  |__| |  \

'
}

prereqs () {

IPTABLES=`whereis iptables | awk '{print $2}'`
IPSET=`whereis ipset | awk '{print $2}'`
CURL=`whereis curl | awk '{print $2}'`
GEOIPLOOKUP=`whereis geoiplookup | awk '{print $2}'`

	if [ "$EUID" -ne 0 ]
		then echo "Please run as root"
		exit 1;
	fi

        if [ ! -f "$IPSET" ]; then
                echo " [!] ipset not found. Please install ipset..";
                exit 1;
	fi

        if [ ! -f "$IPTABLES" ]; then
                echo " [!] iptables not found. Please install iptables..";
                exit 1;
	fi

        if [ ! -f "$CURL" ]; then
                echo " [!] curl not found. Please install curl..";
                exit 1;
	fi

        if [ ! -f "$GEOIPLOOKUP" ]; then
                echo " [!] geoiplookup not found. Please install geoip-common..";
                exit 1;
	fi

	if [ ! -d "$DB_PATH" ]; then
		mkdir $DB_PATH
	fi

	if [ ! -f "$DB_PATH/$DB_NAME.db" ]; then
#DONT INDENT
sqlite3 $DB_PATH/$DB_NAME.db <<'END_SQL'
.timeout 2000
CREATE TABLE IF NOT EXISTS GREPINATOR ( ID INTEGER PRIMARY KEY, Date DATETIME, IP VARCHAR(16), Filter VARCHAR(25), Location VARCHAR(25), Status VARCHAR(25) );
END_SQL
#DONT INDENT
	fi
}

ipset_setup () {

	if ! ipset list -n | grep -Eq "^$IPSET_GREPINATOR$"; then
		if ! ipset create "$IPSET_GREPINATOR" -exist hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0; then
			echo >&2 "Error: while creating the initial ipset"
			exit 1
		fi
	fi

	if ! ipset list -n | grep -Eq "^$IPSET_BLACKLIST_NAME$"; then
		if ! ipset create "$IPSET_BLACKLIST_NAME" -exist hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0; then
			echo >&2 "Error: while creating the initial ipset"
			exit 1
		fi
	fi


	if ! iptables -nvL INPUT | grep -q "match-set $IPSET_GREPINATOR"; then
  		if ! iptables -I INPUT 1 -m set --match-set "$IPSET_GREPINATOR" src -j DROP; then
			echo >&2 "Error: while adding the --match-set ipset rule to iptables"
    			exit 1
		fi
	fi

	if ! iptables -nvL INPUT | grep -q "match-set $IPSET_BLACKLIST_NAME"; then
  		if ! iptables -I INPUT 2 -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
			echo >&2 "Error: while adding the --match-set ipset rule to iptables"
    			exit 1
		fi
	fi
}

sqlite_log () {
FILTER_NAME=`echo $FILTER | sed 's/.filter$//'`
GEOIP=`geoiplookup $IP | sed 's/.*: //'`
sqlite3 $DB_PATH/$DB_NAME.db<<END_SQL
.timeout 30
INSERT INTO GREPINATOR (Date, IP, Filter, Location, Status) VALUES (datetime('now', 'localtime'), '$IP', '$FILTER_NAME', '$GEOIP', 'Blocked');
END_SQL
}

grepinator () {

	ipset create "$IPSET_GREPINATOR_TMP" -exist hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0
	echo "Grepinating filters..."
		for FILTER in $(ls -1 $FILTERDIR)
			do
#				for IP in $(./$FILTERDIR/$FILTER 2>/dev/null); do echo -ne "Blocking $IP"\\r; ipset add $IPSET_GREPINATOR_TMP $IP timeout ${TIMEOUT:-10800} 2>/dev/null; sleep 0.1; done
				for IP in $(./$FILTERDIR/$FILTER 2>/dev/null); do echo -ne "Blocking $IP"\\r; sqlite_log; sleep 0.1; done
			done

#	ENTRIES=`ipset list $IPSET_GREPINATOR_TMP | grep "Number of entries" | awk '{print $NF}'`
#	echo  "Number of attacks found using filters: $ENTRIES"
#	ipset swap $IPSET_GREPINATOR_TMP $IPSET_GREPINATOR
#	ipset destroy $IPSET_GREPINATOR_TMP
#	echo "Added $ENTRIES IP's to Grepinators firewall"
}

blacklist_ips () {
IP_BLACKLIST_TMP=$(mktemp)
	for i in "${BLACKLISTS[@]}"
		do
  			IP_TMP=$(mktemp)
			(( HTTP_RC=$(curl -L -A "blacklist-update/script/github" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i") ))
			if (( HTTP_RC == 200 || HTTP_RC == 302 )); then
				grep -Po '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?' "$IP_TMP" | sed -r 's/^0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)\.0*([0-9]+)$/\1.\2.\3.\4/' >> "$IP_BLACKLIST_TMP"

  			elif (( HTTP_RC == 503 )); then
				echo -e "\\nUnavailable (${HTTP_RC}): $i"
			else
				echo >&2 -e "\\nWarning: curl returned HTTP response code $HTTP_RC for URL $i"
			fi
		rm -f "$IP_TMP"
	done

	ENTRIES=$(cat $IP_BLACKLIST_TMP | wc -l)
	echo;echo "Number of IP's found in Blacklists: $ENTRIES"
	ipset create "$IPSET_TMP_BLACKLIST_NAME" -exist hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0

	for IP in $(cat $IP_BLACKLIST_TMP)
		do
			echo -ne "Blocking IP $IP     "\\r
			ipset add $IPSET_TMP_BLACKLIST_NAME $IP timeout ${TIMEOUT:-10800} 2>/dev/null
		done
	ipset swap $IPSET_TMP_BLACKLIST_NAME $IPSET_BLACKLIST_NAME
	ipset destroy $IPSET_TMP_BLACKLIST_NAME
	echo "Added $ENTRIES IP's to Grepinators BL firewall"
	rm $IP_BLACKLIST_TMP
}

banner
# Make sure we have the right tools
prereqs

# Check command args
if [ $# -lt 1 ]
then
        echo "Usage : $0 <all|filters|blacklists>"
        exit
fi

if [ $1 == "status" ]
	then
		sqlite3 $DB_PATH/$DB_NAME.db<<END_SQL
.headers on
.mode box
select * from GREPINATOR order by id desc limit 10;
END_SQL
	exit 0;
fi

# Create list and iptables rules
ipset_setup

# Work our magic by grabbing the ip's and banning them for 3 hours
grepinator

# get blacklist ips and block
blacklist_ips

