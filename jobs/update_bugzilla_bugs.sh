#!/bin/bash
wget -O bugzilla_bugs.json "https://bugzilla.mozilla.org/rest/bug?include_fields=id,summary,whiteboard,component,status,resolution,creation_time,last_change_time&component=CA%20Certificate%20Compliance&component=CA%20Certificate%20Root%20Program&limit=0&product=NSS"

psql -f ~/certwatch/sql/update_bugzilla_bugs.sql -h bddpcwsql.brad.dc.comodoca.net -d certwatch -U certwatch
