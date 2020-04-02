#!/bin/bash

wget -O ccadb_caowner_information.csv https://ccadb-public.secure.force.com/mozilla/CAInformationReportCSVFormat
if [ -s ccadb_caowner_information.csv ]; then
  psql -f update_caowner_information.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb-public.secure.force.com/mozilla/CAInformationReportCSVFormat"
fi
