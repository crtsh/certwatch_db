#!/bin/bash
psql -f ~/certwatch/linting/do_some_linting.sql -h $PGHOST -d certwatch -U certwatch
