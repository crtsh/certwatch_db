#!/bin/bash

wget -O RootHashes.inc https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/RootHashes.inc
if [ -s RootHashes.inc ]; then
  gcc -o mozilla_root_hashes mozilla_root_hashes.c
  ./mozilla_root_hashes > mozilla_root_hashes.sql
  ../cert_validation_success_monitor/cert_validation_success_monitor > mozilla_cert_validation_success.csv
  psql -f update_mozilla_cert_validation_success.sql -h bddpcwsql.brad.dc.comodoca.net -d certwatch -U certwatch
else
  echo "Failed to download https://hg.mozilla.org/mozilla-central/raw-file/tip/security/manager/ssl/RootHashes.inc"
fi
