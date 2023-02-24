#!/bin/bash
source ~/.profile
psql -f ~/certwatch/sql/determine_ca_trust_purposes.sql -h $PGHOST -d certwatch -U certwatch
