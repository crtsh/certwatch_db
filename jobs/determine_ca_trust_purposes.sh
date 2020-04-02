#!/bin/bash
psql -f ~/certwatch/sql/determine_ca_trust_purposes.sql -h bddpcwsqlv.brad.dc.comodoca.net -d certwatch -U certwatch
