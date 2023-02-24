#!/bin/bash
source ~/.profile
psql -f ~/certwatch/sql/gin_clean_pending_list.sql -h $PGHOST -d certwatch -U certwatch
