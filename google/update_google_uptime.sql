\timing on

\set ON_ERROR_STOP on

\echo Importing Google CT Log Uptimes

BEGIN WORK;

CREATE TEMPORARY TABLE google_uptime (
	LOG_URL				text,
	UPTIME_PERCENTAGE	text
) ON COMMIT DROP;

\COPY google_uptime FROM 'google_uptime.csv' CSV HEADER;

UPDATE ct_log
	SET GOOGLE_UPTIME = NULL;

UPDATE ct_log cl
	SET GOOGLE_UPTIME = gu.UPTIME_PERCENTAGE
	FROM google_uptime gu
	WHERE cl.URL = RTRIM(gu.LOG_URL, '/');

COMMIT WORK;
