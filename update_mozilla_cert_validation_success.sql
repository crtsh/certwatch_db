\timing on

BEGIN WORK;

CREATE TEMPORARY TABLE mozilla_root_hashes_new ( LIKE mozilla_root_hashes INCLUDING INDEXES) ON COMMIT DROP;

\i mozilla_root_hashes.sql

UPDATE mozilla_root_hashes_new mrhn
	SET CERTIFICATE_ID = c.ID
	FROM certificate c
	WHERE mrhn.CERTIFICATE_SHA256 = digest(c.CERTIFICATE, 'sha256');

UPDATE mozilla_root_hashes_new mrhn
	SET DISPLAY_ORDER = sub.ROW_NUMBER,
		CA_OWNER = sub.CA_OWNER
	FROM (
		SELECT mrhn2.CERTIFICATE_ID, coalesce(cc.CA_OWNER, mrh.CA_OWNER) CA_OWNER,
				row_number() OVER (ORDER BY coalesce(cc.CA_OWNER, mrh.CA_OWNER), get_ca_name_attribute(cac.CA_ID))
			FROM mozilla_root_hashes_new mrhn2
				LEFT OUTER JOIN ca_certificate cac ON (mrhn2.CERTIFICATE_ID = cac.CERTIFICATE_ID)
				LEFT OUTER JOIN ccadb_certificate cc ON (mrhn2.CERTIFICATE_ID = cc.CERTIFICATE_ID)
				LEFT OUTER JOIN mozilla_root_hashes mrh ON (mrhn2.CERTIFICATE_ID = mrh.CERTIFICATE_ID)
			WHERE mrhn2.CERTIFICATE_ID = cac.CERTIFICATE_ID
			GROUP BY mrhn2.CERTIFICATE_ID, coalesce(cc.CA_OWNER, mrh.CA_OWNER), cac.CA_ID
		) sub
	WHERE mrhn.CERTIFICATE_ID = sub.CERTIFICATE_ID;

LOCK mozilla_root_hashes;

TRUNCATE mozilla_root_hashes;

INSERT INTO mozilla_root_hashes
	SELECT * FROM mozilla_root_hashes_new;

COMMIT WORK;


BEGIN WORK;

LOCK TABLE mozilla_cert_validation_success_import;

TRUNCATE TABLE mozilla_cert_validation_success_import;

\COPY mozilla_cert_validation_success_import FROM mozilla_cert_validation_success.csv

LOCK TABLE mozilla_cert_validation_success;

TRUNCATE TABLE mozilla_cert_validation_success;

INSERT INTO mozilla_cert_validation_success (
		SUBMISSION_DATE, BIN_NUMBER, COUNT, CERTIFICATE_ID
	)
	SELECT mcvsi.SUBMISSION_DATE, mcvsi.BIN_NUMBER, sum(mcvsi.COUNT), mrh.CERTIFICATE_ID
		FROM mozilla_cert_validation_success_import mcvsi
			LEFT OUTER JOIN mozilla_root_hashes mrh ON (mcvsi.BIN_NUMBER = mrh.BIN_NUMBER)
		WHERE mcvsi.RELEASE = 'release'
		GROUP BY mcvsi.SUBMISSION_DATE, mcvsi.BIN_NUMBER, mrh.CERTIFICATE_ID;

COMMIT WORK;

-- Cache page(s).
SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-certvalidations-by-root,0}'::text[]), 1, 6);

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-certvalidations-by-owner,0}'::text[]), 1, 6);
