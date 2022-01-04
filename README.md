![Grepinator](http://dtors.net/grep.png)

Grepinator is a Fail2ban/Crowdsec alternative written entirely in Bash.

./filters/* has some common filters for sshd/apache2/nginx/bind to look for common patterns and occurences of said patterns. Template.filter should be used for any additional services you want to add. Filters must remain in the filters directory if you want them to be excuted. If you do not want a filter to be executed, remove it from the directory. Errors are surpressed when running filters.

./grepinator.sh is the main script that will take arguments...
