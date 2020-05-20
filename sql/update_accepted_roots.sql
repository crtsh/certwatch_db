\timing on

\set ON_ERROR_STOP on

BEGIN WORK;

CREATE TEMPORARY TABLE accepted_roots_import (
	CT_LOG_ID		integer,
	GETROOTS_DATA	jsonb
) ON COMMIT DROP;

\COPY accepted_roots_import FROM '~/certwatch/jobs/accepted-roots.tsv';

LOCK accepted_roots;

TRUNCATE accepted_roots;

INSERT INTO accepted_roots (CT_LOG_ID, CERTIFICATE_ID)
	SELECT CT_LOG_ID,
			import_cert(decode(jsonb_array_elements_text(GETROOTS_DATA->'certificates'), 'base64')) CERTIFICATE_ID
		FROM accepted_roots_import
		GROUP BY CT_LOG_ID, CERTIFICATE_ID;

COMMIT WORK;

--SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{get-roots,0}'::text[]), 1, 6);
