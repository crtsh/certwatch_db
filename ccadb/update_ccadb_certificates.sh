#!/bin/bash

# Process CCADB certificates.
wget -O ccadb_all_certificate_records.csv.new https://ccadb-public.secure.force.com/ccadb/AllCertificateRecordsCSVFormat
if [ -s ccadb_all_certificate_records.csv.new ]; then
  cp ccadb_all_certificate_records.csv.new ccadb_all_certificate_records.csv
  psql -f update_ccadb_certificates.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb-public.secure.force.com/ccadb/AllCertificateRecordsCSVFormat"
fi

# Check the Test Websites and update the monitoring page.
cd ~/certwatch/test_websites_monitor/bin
./test_websites_monitor
