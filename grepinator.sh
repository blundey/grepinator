#!/bin/bash 
#
# Grepinator v0.0.1-alpha
#
# Grepinator is a series of bash scripts utilising the power of grep and regex.
#
# See Readme.md for usage and instructions.


######################################################
# GLOBAL VARS (change as needed)
FILTERDIR="./filters"
IPSET_GREPINATOR="grepinator"
IPSET_GREPINATOR_TMP=${IPSET_GREPINATOR}-tmp
IPSET_BLACKLIST_NAME="grepinatorBL"
IPSET_TMP_BLACKLIST_NAME=${IPSET_BLACKLIST_NAME}-tmp
DB_NAME="grepinator"
DB_PATH="/var/log/grepinator"
DISPLAY="box" # use modes box or column. Use column for older sqlite3 versions
MAXELEM=131072
TIMEOUT="10800" # 3 hours
BLACKLISTS=(
#   "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"  # TOR Exit Nodes
    "http://danger.rulez.sk/projects/bruteforceblocker/blist.php" # BruteForceBlocker IP List
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
                echo " [!] geoiplookup not found. Please install geoip-bin..";
                exit 1;
	fi

	if [ ! -d "$DB_PATH" ]; then
		mkdir $DB_PATH
	fi

	if [ ! -f "$DB_PATH/$DB_NAME.db" ]; then
		sqlite3 $DB_PATH/$DB_NAME.db "CREATE TABLE IF NOT EXISTS GREPINATOR ( ID INTEGER PRIMARY KEY, Date DATETIME, IP VARCHAR(16), Filter VARCHAR(25), Location VARCHAR(25), Status VARCHAR(25) );"
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

RESULT=`sqlite3 /var/log/grepinator/grepinator.db "select count(*) from GREPINATOR where IP='$IP';"`

	if [ $RESULT -eq 0 ]
	then
		FILTER_NAME=`echo $FILTER | sed 's/.filter$//'`
		GEOIP=`geoiplookup $IP | sed 's/.*: //'`
		ENTRIES=$((ENTRIES+1))
			sqlite3 $DB_PATH/$DB_NAME.db "INSERT INTO GREPINATOR (Date, IP, Filter, Location, Status) VALUES (datetime('now', 'localtime'), '$IP', '$FILTER_NAME', '$GEOIP', 'Threat');"
	fi
}

filter () {

	echo "Grepinating filters..."
	ENTRIES=0
		for FILTER in $(ls -1 $FILTERDIR)
			do
				for IP in $(./$FILTERDIR/$FILTER 2>/dev/null); do echo -ne "Checking $IP"\\r; sqlite_log; sleep 0.1; done
			done

	echo  "Number of new attacks found using filters: $ENTRIES"
}

grepinator () {

	ipset create "$IPSET_GREPINATOR_TMP" -exist hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0
	echo "Grepinating IP's..."
	ENTRIES=0
		for IP in $(sqlite3 $DB_PATH/$DB_NAME.db "select IP from GREPINATOR where Status='Threat';")
			do
				echo -ne "Blocking $IP"\\r; ipset add $IPSET_GREPINATOR_TMP $IP timeout ${TIMEOUT:-10800} 2>/dev/null;
				ENTRIES=$((ENTRIES+1))
				sqlite3 $DB_PATH/$DB_NAME.db "UPDATE GREPINATOR SET Status='Blocked' WHERE IP='$IP';"
				sleep 0.1;
			done

	ipset swap $IPSET_GREPINATOR_TMP $IPSET_GREPINATOR
	ipset destroy $IPSET_GREPINATOR_TMP
	echo "Added $ENTRIES IP's to Grepinators firewall"
}

blacklist_ips () {
IP_BLACKLIST_TMP=$(mktemp)
	for i in "${BLACKLISTS[@]}"
		do
  			IP_TMP=$(mktemp)
			(( HTTP_RC=$(curl -L -A "grepinator" --connect-timeout 10 --max-time 10 -o "$IP_TMP" -s -w "%{http_code}" "$i") ))
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

reset() {
	sqlite3 $DB_PATH/$DB_NAME.db "DELETE FROM GREPINATOR;"
	echo "Database $DB_NAME has been cleared"
	ipset flush $IPSET_GREPINATOR
	ipset flush $IPSET_BLACKLIST_NAME
	echo "Blocklists cleared"
}

status() {
	sqlite3 -header -$DISPLAY $DB_PATH/$DB_NAME.db "select * from GREPINATOR order by id desc limit 10;"
	iptables -nvL INPUT | grep -e 'grepinator src$' | awk '{print "Grepinator Packets Dropped: " $1}'
	iptables -nvL INPUT | grep -e 'grepinatorBL src$' | awk '{print "Grepinator Blacklists Packets Dropped: " $1}'
	exit 0;
}

usage() {
        echo "Usage : $0 <all|filters|blacklists|log|status|reset>"
	cat <<_EOF

	all          - Run all filters and blacklists and BLOCK
	filters      - Run filters and BLOCK
	blacklists   - Update and block blacklisted IP's only. Should only be ran once a day.
	log          - Run filters and LOG only. (No blocking occurs)
	status       - Show status of whats been blocked
	reset        - Clear the database of logged IP's
_EOF
}

# Check command args
if [ $# -lt 1 ]
then
	usage
	exit 0
fi

case "$1" in

all)
	banner
	prereqs
	ipset_setup
	filter
	grepinator
	blacklist_ips
    ;;
filters)
	banner
	prereqs
	ipset_setup
	filter
	grepinator
    ;;
blacklists)
	banner
	prereqs
	ipset_setup
	blacklist_ips
    ;;
log)
	banner
	prereqs
	ipset_setup
	filter
   ;;
status) banner
	status
   ;;
reset)
	banner
	reset
   ;;
*)
	banner
	usage
   ;;
esac

