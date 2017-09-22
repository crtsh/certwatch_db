#!/bin/bash
PGHOST=localhost
cd /root/certwatch_tasks

wget -O ccadb_caowner_information.csv https://ccadb-public.secure.force.com/mozilla/CAInformationReportCSVFormat
psql -v ON_ERROR_STOP=1 -f /root/svn/CertWatch/trunk/ccadb/update_caowner_information.sql -h $PGHOST -U certwatch certwatch
