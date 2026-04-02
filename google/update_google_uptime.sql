\timing on

\set ON_ERROR_STOP on

\echo Importing Google CT Log Uptimes

BEGIN WORK;

CREATE TEMPORARY TABLE google_uptime_90d (
	LOG_URL				text,
	UPTIME_PERCENTAGE	text
) ON COMMIT DROP;

\COPY google_uptime_90d FROM 'min_uptime_90d.csv' CSV HEADER;

CREATE TEMPORARY TABLE google_uptime_24h (
	LOG_URL				text,
	UPTIME_PERCENTAGE	text
) ON COMMIT DROP;

\COPY google_uptime_24h FROM 'endpoint_min_uptime_24h.csv' CSV HEADER DELIMITER ' ';

UPDATE ct_log
	SET GOOGLE_UPTIME = NULL,
		GOOGLE_UPTIME_24H = NULL;

UPDATE ct_log cl
	SET GOOGLE_UPTIME = gu90.UPTIME_PERCENTAGE
	FROM google_uptime_90d gu90
	WHERE coalesce(cl.SUBMISSION_URL, cl.URL) = RTRIM(gu90.LOG_URL, '/');

UPDATE ct_log cl
	SET GOOGLE_UPTIME_24H = gu24.UPTIME_PERCENTAGE
	FROM google_uptime_24h gu24
	WHERE coalesce(cl.SUBMISSION_URL, cl.URL) = RTRIM(gu24.LOG_URL, '/');

COMMIT WORK;
