\timing on

\set ON_ERROR_STOP on

BEGIN WORK;

CREATE TEMPORARY TABLE bugzilla_bugs_import (
	BUGS_DATA			jsonb
) ON COMMIT DROP;

\COPY bugzilla_bugs_import FROM PROGRAM 'sed -e ''s/\\/\\\\/g'' ~/certwatch/jobs/bugzilla_bugs.json';

CREATE TEMPORARY TABLE bugzilla_bug_temp (
	BUG_DATA			jsonb
) ON COMMIT DROP;

INSERT INTO bugzilla_bug_temp ( BUG_DATA )
	SELECT jsonb_array_elements(bbi.BUGS_DATA->'bugs')
		FROM bugzilla_bugs_import bbi;

CREATE TEMPORARY TABLE bugzilla_bug_temp2 (
	LIKE bugzilla_bug
);

INSERT INTO bugzilla_bug_temp2 ( ID, SUMMARY, WHITEBOARD, COMPONENT, STATUS, RESOLUTION, CREATION_TIME, LAST_CHANGE_TIME )
	SELECT (bbt.BUG_DATA->>'id')::bigint, bbt.BUG_DATA->>'summary', bbt.BUG_DATA->>'whiteboard', bbt.BUG_DATA->>'component', bbt.BUG_DATA->>'status', bbt.BUG_DATA->>'resolution', (bbt.BUG_DATA->>'creation_time')::timestamp, (bbt.BUG_DATA->>'last_change_time')::timestamp
		FROM bugzilla_bug_temp bbt;

INSERT INTO bugzilla_bug ( ID, SUMMARY, WHITEBOARD, COMPONENT, STATUS, RESOLUTION, CREATION_TIME, LAST_CHANGE_TIME )
	SELECT bbt2.ID, bbt2.SUMMARY, bbt2.WHITEBOARD, bbt2.COMPONENT, bbt2.STATUS, bbt2.RESOLUTION, bbt2.CREATION_TIME, bbt2.LAST_CHANGE_TIME
		FROM bugzilla_bug_temp2 bbt2
	ON CONFLICT ON CONSTRAINT bb_pk
		DO UPDATE SET SUMMARY = excluded.SUMMARY,
			WHITEBOARD = excluded.WHITEBOARD,
			COMPONENT = excluded.COMPONENT,
			STATUS = excluded.STATUS,
			RESOLUTION = excluded.RESOLUTION,
			CREATION_TIME = excluded.CREATION_TIME,
			LAST_CHANGE_TIME = excluded.LAST_CHANGE_TIME;

COMMIT WORK;
