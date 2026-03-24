#!/bin/bash
source ~/.profile
wget -O ~/certwatch/google/google_uptime_90d.csv https://www.gstatic.com/ct/compliance/min_uptime.csv
wget -O /dev/stdout https://www.gstatic.com/ct/compliance/endpoint_uptime_24h.csv | awk -F, '{ if ($1 not in mins) { mins[$1] = $3 } if (mins[$1] > $3) { mins[$1] = $3 } } END { for (i in mins) { print i,mins[i] } }' > ~/certwatch/google/endpoint_uptime_24h.csv
psql -f ~/certwatch/google/update_google_uptime.sql -h $PGHOST -d certwatch -U certwatch
