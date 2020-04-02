#!/bin/bash
psql -f ~/certwatch/sql/regular_maintenance.sql -h bddpcwsqlv.brad.dc.comodoca.net -d certwatch -U certwatch
