![Grepinator](http://dtors.net/grep.png)

Grepinator is a Fail2ban/Crowdsec alternative written entirely in Bash.

./filters/* has some executable filters (scripts) for common services such as sshd/apache2/nginx/bind. The filters will look for common patterns and count occurences of said patterns. Template.filter can be used for any additional services you want to grep for patterns on. Filters must remain in the filters directory if you want them to be executed. If you do not want a filter to be executed, remove it from the directory. Errors are surpressed when running filters, so leaving filters there for services that do not exist will not result in an error. You can create any script/file that returns ip's on a new line to be included as a filter for Grepinator to parse.

./grepinator.sh is the main script that does the majority of the heavy lifting:
```sh
┌──(root💀zombie)-[~/grepinator]
└─# ./grepinator.sh       


   ______                _             __
  / ____/_______  ____  (_)___  ____ _/ /_____  _____
 / / __/ ___/ _ \/ __ \/ / __ \/ __ `/ __/ __ \/ ___/
/ /_/ / /  /  __/ /_/ / / / / / /_/ / /_/ /_/ / /
\____/_/   \___/ .___/_/_/ /_/\__,_/\__/\____/_/
              /_/

Usage : ./grepinator.sh <all|filters|blacklists|log|status|reset>

	all          - Run all filters and blacklists and BLOCK
	daemon       - Run Grepinator in daemon mode (no output)
	filters      - Run filters and BLOCK
	blacklists   - Update and block blacklisted IP's only. Should only be ran once a day.
	log          - Run filters and LOG only. (No blocking occurs)
	status       - Show status of whats been blocked
	reset        - Clear the database of logged IP's
	stop         - Stop the daemon
	top          - Show table of blocked ip's in realtime
	version      - Show version

                                                           
