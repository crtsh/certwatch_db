#!/bin/bash
source ~/.profile
wget -O bugzilla_bugs.json "https://bugzilla.mozilla.org/rest/bug?include_fields=id,summary,whiteboard,component,status,resolution,creation_time,last_change_time&product=NSS&component=CA%20Certificates%20Code&component=Libraries&product=CA%20Program&component=CA%20Certificate%20Compliance&component=CA%20Certificate%20Root%20Program&limit=0"
psql -f ~/certwatch/sql/update_bugzilla_bugs.sql -h $PGHOST -d certwatch -U certwatch
