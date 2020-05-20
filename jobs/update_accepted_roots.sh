#!/bin/bash
ALLGETROOTS=`mktemp`
WORKDIR=`mktemp -d`
TSVTEMP=`mktemp`

psql -h $PGHOST -d certwatch -U certwatch -c "\COPY (SELECT ctl.ID::text || ' ' || (ctl.URL || '/ct/v1/get-roots') FROM ct_log ctl WHERE ctl.IS_ACTIVE) TO '$ALLGETROOTS'"

cd $WORKDIR
while read line; do
  items=($line)
  wget -O get-roots.${items[0]} ${items[1]}
  echo -en "${items[0]}\t" >> $TSVTEMP
  cat get-roots.${items[0]} >> $TSVTEMP
  echo >> $TSVTEMP
done <$ALLGETROOTS

sort $TSVTEMP | uniq | sed '/^[[:space:]]*$/d' > ~/certwatch/jobs/accepted-roots.tsv

psql -f ~/certwatch/sql/update_accepted_roots.sql -h $PGHOST -d certwatch -U certwatch

rm -rf $ALLGETROOTS $WORKDIR $TSVTEMP
