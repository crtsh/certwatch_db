#!/bin/bash
source ~/.profile

# Process CCADB certificates.
wget -O ccadb_all_certificate_records.csv.new https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
RESULT=$?
if [ "$RESULT" -eq "0" ]; then
  mv ccadb_all_certificate_records.csv.new ccadb_all_certificate_records.csv
  sed -i "s/,$//g" ccadb_all_certificate_records.csv
  psql -f update_ccadb_certificates.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2"
fi

# Check the Test Websites and update the monitoring page.
cd ~/certwatch/test_websites_monitor/bin
./test_websites_monitor
