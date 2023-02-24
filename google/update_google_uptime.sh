#!/bin/bash
source ~/.profile
wget -O ~/certwatch/google/google_uptime.csv https://www.gstatic.com/ct/compliance/uptime.csv
psql -f ~/certwatch/google/update_google_uptime.sql -h $PGHOST -d certwatch -U certwatch
