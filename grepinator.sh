#!/usr/bin/env /bin/bash
#
# Grepinator v0.0.70
#
# Grepinator is a series of bash scripts utilising the power of grep and regex.
#
# See Readme.md for usage and instructions.

######################################################
VERSION="0.0.70"
IPSET_GREPINATOR="grepinator"
IPSET_BLACKLIST_NAME="grepinator-blacklist"
IPSET_TMP_BLACKLIST_NAME=${IPSET_BLACKLIST_NAME}-tmp

if [[ ! -f /etc/grepinator/grepinator.conf ]]; then
	if [[ ! -f ./grepinator.conf ]]; then
		echo "Error: grepinator.conf not found."
	else
		source ./grepinator.conf
	fi
else
	source /etc/grepinator/grepinator.conf
fi
####################################################

banner () {
echo '

   ______                _             __
  / ____/_______  ____  (_)___  ____ _/ /_____  _____
 / / __/ ___/ _ \/ __ \/ / __ \/ __ `/ __/ __ \/ ___/
/ /_/ / /  /  __/ /_/ / / / / / /_/ / /_/ /_/ / /
\____/_/   \___/ .___/_/_/ /_/\__,_/\__/\____/_/
              /_/
'
}

prereqs () {

IPTABLES=$(whereis iptables | awk '{print $2}')
IPSET=$(whereis ipset | awk '{print $2}')
CURL=$(whereis curl | awk '{print $2}')
SQLITE=$(whereis sqlite3 | awk '{print $2}')
GEOIPLOOKUP=$(whereis geoiplookup | awk '{print $2}')

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

        if [ ! -f "$SQLITE" ]; then
                echo " [!] sqlite3 not found. Please install sqlite3..";
                exit 1;
	fi

	if [ ! -d "${DB_PATH:-/var/log/grepinator}" ]; then
		mkdir ${DB_PATH:-/var/log/grepinator}
	fi

	if [ ! -f "${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db" ]; then
		sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "CREATE TABLE IF NOT EXISTS GREPINATOR ( ID INTEGER PRIMARY KEY, Date DATETIME, IP VARCHAR(16), Filter VARCHAR(25), Location VARCHAR(25), Status VARCHAR(25) );"
	fi
}

ipset_setup () {

	if ! ipset list -n | grep -Eq "^$IPSET_GREPINATOR$"; then
		if ! ipset create "$IPSET_GREPINATOR" hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536}; then
			echo >&2 "Error: while creating the initial ipset"
			exit 1
		fi
	fi

	if ! ipset list -n | grep -Eq "^$IPSET_BLACKLIST_NAME$"; then
		if ! ipset create "$IPSET_BLACKLIST_NAME" hash:net family inet hashsize 16384 maxelem ${MAXELEM:-65536} timeout 0; then
			echo >&2 "Error: while creating the initial ipset"
			exit 1
		fi
	fi


	if ! iptables -nvL INPUT | grep -q "match-set $IPSET_GREPINATOR src"; then
  		if ! iptables -I INPUT 1 -m set --match-set "$IPSET_GREPINATOR" src -j DROP; then
			echo >&2 "Error: while adding the --match-set ipset rule to iptables"
    			exit 1
		fi
	fi

	if ! iptables -nvL INPUT | grep -q "match-set $IPSET_BLACKLIST_NAME src"; then
  		if ! iptables -I INPUT 2 -m set --match-set "$IPSET_BLACKLIST_NAME" src -j DROP; then
			echo >&2 "Error: while adding the --match-set ipset rule to iptables"
    			exit 1
		fi
	fi
}

valid_ip () {

	local  ip=$1
	local  STAT=1

	if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		OIFS=$IFS
		IFS='.'
		ip=($ip)
		IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        	STAT=$?
	fi
    return $STAT
}

sqlite_log () {

RESULT=$(sqlite3 /var/log/grepinator/grepinator.db "select count(*) from GREPINATOR where IP='$IP';")

	if [ $RESULT -eq 0 ]; then
		WHITELISTED=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT count(*) FROM GREPINATOR WHERE IP='$IP' AND Status='Whitelisted';")
		if [ "$WHITELISTED" -eq 0 ]; then
			FILTER_NAME=$(echo $FILTER | sed 's/.filter$//')

			if [[ $IP =~ '^10\..*' || $IP =~ ^192.168.* || $IP =~ ^172.[16..32].* ]]; then
				GEOIP="Private IP Address"
			else
				GEOIP=$(geoiplookup $IP | sed 's/.*: //')
			fi

			ENTRIES=$((ENTRIES+1))
			sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "INSERT INTO GREPINATOR (Date, IP, Filter, Location, Status) VALUES (datetime('now', 'localtime'), '$IP', '$FILTER_NAME', '$GEOIP', 'Threat');"
		fi
	fi
}

filter () {

	echo "Grepinating filters..."
	ENTRIES=0
		for FILTER in $(ls -1 ${FILTER_DIR:-/etc/grepinator/filters})
			do
				for IP in $(${FILTER_DIR:-/etc/grepinator/filters}/$FILTER 2>/dev/null); do echo -ne "Checking $IP"\\r; sqlite_log; sleep 0.1; done
			done

	echo  "Number of new attacks found using filters: $ENTRIES"
}

grepinator () {

UPDATE=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "select count(*) from GREPINATOR where Status='Threat';")

	if [ "$UPDATE" -eq 0 ]; then
		echo "No IP's to add to ipset. I'll be back.."
	else
	echo "Grepinating IP's..."
	ENTRIES=0
		for IP in $(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT IP FROM GREPINATOR WHERE Status='Threat';")
			do
				echo -ne "Blocking $IP"\\r; ipset add $IPSET_GREPINATOR $IP 2>/dev/null;
				ENTRIES=$((ENTRIES+1))
				sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "UPDATE GREPINATOR SET Status='Blocked' WHERE IP='$IP';"
				sleep 0.1;
			done

		echo "Added $ENTRIES IP's to Grepinators firewall"
	fi
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
			ipset add $IPSET_TMP_BLACKLIST_NAME $IP timeout ${TIMEOUT:-0} 2>/dev/null
		done
	ipset swap $IPSET_TMP_BLACKLIST_NAME $IPSET_BLACKLIST_NAME
	ipset destroy $IPSET_TMP_BLACKLIST_NAME
	echo "Added $ENTRIES IP's to Grepinators BL firewall"
	rm $IP_BLACKLIST_TMP
}

daemon () {

	echo $$ > /var/run/grepinator.pid
	while true; do
		prereqs
		ipset_setup
		filter
		grepinator
		sleep ${INTERVAL:-5};
	done
}

report () {
actionban = curl --fail 'https://api.abuseipdb.com/api/v2/report' \
    -H 'Accept: application/json' \
    -H 'Key: $APIKEY' \
    --data-urlencode 'comment=IP detected by Grepinator performing mutiple attacks.' \
    --data-urlencode 'ip=$IP' \
    --data 'categories=https://www.abuseipdb.com/categories>'
}

stop () {
	if [ -f /var/run/grepinator.pid ]; then
		PID=$(cat /var/run/grepinator.pid)
		kill -9 $PID 2>/dev/null
		rm /var/run/grepinator.pid
		echo "Grepinator stopped. Ill be back.."
	else
		echo "Grepinator not running. Nothing to kill."
	fi
}

reset () {
	sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "DELETE FROM GREPINATOR;"
	echo "Database ${DB_NAME:-grepinator} has been cleared"
	ipset flush $IPSET_GREPINATOR
	ipset flush $IPSET_BLACKLIST_NAME
	echo "IPset Blocklists cleared"
	exit 0;
}

db_display_mode () {

SQLITE_VER=$(sqlite3 -version | awk '{print $1}' | tr -d '.,')

        if [ $SQLITE_VER -ge "3330" ]; then
                DISPLAY="box"
        else
                DISPLAY="column"
        fi
}

status () {
	db_display_mode
	sqlite3 -header -$DISPLAY ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT * from GREPINATOR ORDER BY id DESC LIMIT ${COUNT:-10};"
	echo
	for F in $(ls -1 $FILTER_DIR); do 
		NAME=$(echo $F | sed 's/.filter//')
		local COUNT=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT count(*) from GREPINATOR WHERE Filter='$NAME';")
		if [ "$COUNT" -gt 0 ]; then
			echo "Attacks detected by $F: $COUNT"
		fi
	done
        echo -n "Country that hates you the most: "
	sqlite3 /var/log/grepinator/grepinator.db  "select Location from GREPINATOR;" | sort | uniq -c | sort -n | tail -n 1 | tr '[0-9]' ' ' | sed 's/ //g'
	iptables -nvL INPUT | grep -e  "$IPSET_GREPINATOR src$" | awk '{print "Grepinator Packets Dropped: " $1}'
	iptables -nvL INPUT | grep -e "$IPSET_BLACKLIST_NAME src$" | awk '{print "Grepinator Blacklists Packets Dropped: " $1}'
}


whitelist () {

	if [[ "$AOR" == "add"  && $CIDR =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		EXISTS=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT count(*) FROM GREPINATOR WHERE IP='$CIDR';")
		if [ "$EXISTS" -eq 1 ]; then
			STATUS=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT Status FROM GREPINATOR WHERE IP='$CIDR';")
			if [ "$STATUS" == "Blocked" ] || [ "$STATUS" == "Threat" ]; then
				echo "Whitelisting $CIDR.."
				sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "UPDATE GREPINATOR SET Status='Whitelisted' WHERE IP='$CIDR';"
				ipset del $IPSET_GREPINATOR $CIDR 2>/dev/null
				echo "Done."
			fi
		else
			if [[ $CIDR =~ '^10\..*' || $CIDR =~ ^192.168.* || $CIDR =~ ^172.[16..32].* ]]; then
                                GEOIP="Private IP Address"
                        else
                                GEOIP=$(geoiplookup $CIDR | sed 's/.*: //')
                        fi
			echo "Whitelisting $CIDR.."
			sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "INSERT INTO GREPINATOR (Date, IP, Filter, Location, Status) VALUES (datetime('now', 'localtime'), '$CIDR', 'Manual', '$GEOIP', 'Whitelisted');"
			unset GEOIP
			echo "Done."
		fi


	elif [[ "$AOR" == "remove" && $CIDR =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
		EXISTS=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT count(*) FROM GREPINATOR WHERE IP='$CIDR';")
		if [ "$EXISTS" -eq 1 ]; then
			STATUS=$(sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "SELECT Status FROM GREPINATOR WHERE IP='$CIDR';")
			if [ "$STATUS" == "Whitelisted" ]; then
				echo "Removing $CIDR from whitelist.."
				sqlite3 ${DB_PATH:-/var/log/grepinator}/${DB_NAME:-grepinator}.db "UPDATE GREPINATOR SET Status='Blocked' WHERE IP='$CIDR';"
				ipset add $IPSET_GREPINATOR $CIDR
			fi
		else
			echo "Remove failed. IP not found."
		fi


	else
		echo "Option not recognised. Must use add or remove followed by the IP or CIDR"
	fi
}



usage() {
        echo "Usage : $0 <choose from options below>"
	cat <<_EOF

	all          			- Run all filters and blacklists and BLOCK
	daemon       			- Run Grepinator in daemon mode (no output)
	filters      			- Run filters and BLOCK
	blacklists   			- Update and block blacklisted IP's only. Should only be ran once a day
	log          			- Run filters and LOG only. (No blocking occurs)
	status [n]   			- Show status of whats been blocked. n = number of lines to display
	reset        			- Clear the database of logged IP's
	stop         			- Stop the daemon
	top [n]      			- Show table of blocked IP's in realtime. n = number of lines to display
	whitelist <add|remove> <ip> 	- Add or remove IP from the whitelist
	version      			- Show version

_EOF

}

# Check command args
if [ $# -lt 1 ]
then
	banner
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
watcher)
	daemon
    ;;
daemon)
	nohup setsid $0 watcher 2>/var/log/grepinator/grepinator.err >/var/log/grepinator/grepinator.log &
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
status)
	banner
	prereqs
	COUNT=$2
	status
   ;;
reset)
	banner
	prereqs
	reset
   ;;
stop)
	banner
	prereqs
	stop
  ;;
top)
	banner
	prereqs
	watch $0 status $2
   ;;
whitelist)
	banner
	prereqs
	AOR=$2
	CIDR=$3
	whitelist
  ;;
version)
	banner
	echo $VERSION
  ;;
*)
	banner
	usage
   ;;
esac

