![Grepinator](http://dtors.net/grep.png)

Grepinator is a Fail2ban/Crowdsec alternative written entirely in Bash.

./filters/* has some executable filters (scripts) for common services such as sshd/apache2/nginx/bind. The filters will look for common patterns and count occurences of said patterns. Template.filter should be used for any additional services you want to create. Filters must remain in the filters directory if you want them to be executed. If you do not want a filter to be executed, remove it from the directory. Errors are surpressed when running filters, so leaving filters there for services that do not exist will not result in an error.

./grepinator.sh is the main script that does the majority of the heavy lifting:
```sh
┌──(root💀zombie)-[~/grepinator]
└─# ./grepinator.sh       

____ ____ ____ ___  _ _  _ ____ ___ ____ ____
| __ |__/ |___ |__] | |\ | |__|  |  |  | |__/
|__] |  \ |___ |    | | \| |  |  |  |__| |  \


Usage : ./grepinator.sh <all|filters|blacklists|status>

all          - Run all filters and retrieve blacklists (Blacklists can take a while to add)
filters      - Run filters only, not blacklists
blacklists   - Update and run blacklists only. Should only be ran once a day
status       - Show status of whats been blocked
