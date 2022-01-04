![Grepinator](http://dtors.net/grep.png)

Grepinator is a Fail2ban/Crowdsec alternative written entirely in Bash.

./filters/* has some common filters for sshd/apache2/nginx/bind to look for common patterns and occurences of said patterns. Template.filter should be used for any additional services you want to add. Filters must remain in the filters directory if you want them to be excuted. If you do not want a filter to be executed, remove it from the directory. Errors are surpressed when running filters.

./grepinator.sh is the main script that will take arguments:
```sh
┌──(root💀zombie)-[~/grepinator]
└─# ./grepinator.sh       

____ ____ ____ ___  _ _  _ ____ ___ ____ ____
| __ |__/ |___ |__] | |\ | |__|  |  |  | |__/
|__] |  \ |___ |    | | \| |  |  |  |__| |  \


Usage : ./grepinator.sh <all|filters|blacklists|status>

all          - Run all filters and retrieve blacklists (Blacklists can take a while to add)
filters      - Run filters only. Not blacklists
blacklists   - Update and run blacklists only. Should only be ran once a day
status       - Show status of whats been blocked
