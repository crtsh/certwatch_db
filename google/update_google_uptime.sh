#!/bin/bash
PGHOST=localhost
cd /root/certwatch_tasks

wget -O google_uptime.csv https://www.gstatic.com/ct/compliance/uptime.csv
psql -v ON_ERROR_STOP=1 -f /root/svn/CertWatch/trunk/google/update_google_uptime.sql -h $PGHOST -U certwatch certwatch
