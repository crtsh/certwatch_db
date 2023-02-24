#!/bin/bash
source ~/.profile
psql -f ~/certwatch/sql/regular_maintenance.sql -h $PGHOST -d certwatch -U certwatch
