#!/bin/bash
source ~/.profile
wget -O ~/certwatch/google/min_uptime_90d.csv https://www.gstatic.com/ct/compliance/min_uptime.csv
wget -O /dev/stdout https://www.gstatic.com/ct/compliance/endpoint_uptime_24h.csv | awk -f $(dirname "$0")/find_min_uptime.awk > ~/certwatch/google/endpoint_min_uptime_24h.csv
psql -f ~/certwatch/google/update_google_uptime.sql -h $PGHOST -d certwatch -U certwatch
