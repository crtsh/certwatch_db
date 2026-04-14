#!/bin/bash
source ~/.profile

# Process CCADB certificates.
wget -O AllCertificateRecordsCSVFormatV4a.new https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4a
RESULT=$?
if [ "$RESULT" -eq "0" ]; then
  mv AllCertificateRecordsCSVFormatV4a.new AllCertificateRecordsCSVFormatV4a
  sed -i "s/,$//g" AllCertificateRecordsCSVFormatV4a
  psql -f update_ccadb_certificates.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4a"
fi

wget -O AllCertificateRecordsCSVFormatV4b.new https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatV4b
RESULT=$?
if [ "$RESULT" -eq "0" ]; then
  mv AllCertificateRecordsCSVFormatV4b.new AllCertificateRecordsCSVFormatV4b
  sed -i "s/,$//g" AllCertificateRecordsCSVFormatV4b
  psql -f update_ccadb_certificates.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4b"
fi

# Process Root Trust Bit settings.
wget -O ccadb_all_root_trust_bits.csv.new https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV
RESULT=$?
if [ "$RESULT" -eq "0" ]; then
  mv ccadb_all_root_trust_bits.csv.new ccadb_all_root_trust_bits.csv
  sed -i "s/,$//g" ccadb_all_root_trust_bits.csv
  psql -f update_ccadb_root_trust_bits.sql -h $PGHOST -d certwatch -U certwatch
else
  echo "Failed to download https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV"
fi

# Check the Test Websites and update the monitoring page.
cd ~/certwatch/test_websites_monitor/bin
./test_websites_monitor
