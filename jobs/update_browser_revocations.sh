#!/bin/bash
source ~/.profile

# Get latest OneCRL.
cd ~/certwatch/jobs
wget -O onecrl.json https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/records

# Get latest CRLSet.
./crlset fetch > google_crlset.bin
./crlset dump google_crlset.bin | uniq > google_crlset.csv
./crlset dumpSPKIs google_crlset.bin | uniq >> google_crlset.csv

# Process browser revocations.
psql -f ~/certwatch/sql/update_browser_revocations.sql -h $PGHOST -d certwatch -U certwatch
