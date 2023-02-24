#!/bin/bash
source ~/.profile

wget -O ccadb_caowner_information.csv.new https://ccadb.my.salesforce-sites.com/mozilla/CAInformationReportCSVFormat
RESULT=$?
if [ "$RESULT" -eq "0" ]; then
  mv ccadb_caowner_information.csv.new ccadb_caowner_information.csv
  psql -f update_caowner_information.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb.my.salesforce-sites.com/mozilla/CAInformationReportCSVFormat"
fi
