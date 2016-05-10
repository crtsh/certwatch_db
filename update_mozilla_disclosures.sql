CREATE TABLE mozilla_disclosure_import (
	RECORD_TYPE				text,
	CA_OWNER_OR_CERT_NAME	text,
	ISSUER_CN				text,
	ISSUER_O				text,
	SUBJECT_CN				text,
	SUBJECT_O				text,
	CERT_SHA1				text,
	VALID_FROM_GMT			text,
	VALID_TO_GMT			text,
	SIGNING_KEY_PARAMETERS	text,
	SIGNATURE_ALGORITHM		text,
	EXTENDED_KEY_USAGE		text,
	CP_CPS_SAME_AS_PARENT	text,
	CP_URL					text,
	CPS_URL					text,
	AUDITS_SAME_AS_PARENT	text,
	STANDARD_AUDIT_URL		text,
	BR_AUDIT_URL			text,
	AUDITOR					text,
	STANDARD_AUDIT_DATE		text,
	MGMT_ASSERTIONS_BY		text
);

\COPY mozilla_disclosure_import FROM 'mozilla_disclosures.csv' CSV HEADER;

CREATE TABLE mozilla_disclosure_temp AS
SELECT		c.ID	CERTIFICATE_ID,
		NULL::integer	PARENT_CERTIFICATE_ID,
		mdi.RECORD_TYPE,
		CASE WHEN (mdi.CP_CPS_SAME_AS_PARENT = '') THEN NULL
			ELSE (mdi.CP_CPS_SAME_AS_PARENT = 'TRUE')
		END CP_CPS_SAME_AS_PARENT,
		CASE WHEN (mdi.CP_URL = '') THEN NULL
			ELSE mdi.CP_URL
		END CP_URL,
		CASE WHEN (mdi.CPS_URL = '') THEN NULL
			ELSE mdi.CPS_URL
		END CPS_URL,
		CASE WHEN (mdi.AUDITS_SAME_AS_PARENT = '') THEN NULL
			ELSE (mdi.AUDITS_SAME_AS_PARENT = 'TRUE')
		END AUDITS_SAME_AS_PARENT,
		CASE WHEN (mdi.STANDARD_AUDIT_URL = '') THEN NULL
			ELSE mdi.STANDARD_AUDIT_URL
		END STANDARD_AUDIT_URL,
		CASE WHEN (mdi.BR_AUDIT_URL = '') THEN NULL
			ELSE mdi.BR_AUDIT_URL
		END BR_AUDIT_URL,
		CASE WHEN (mdi.AUDITOR = '') THEN NULL
			ELSE mdi.AUDITOR
		END AUDITOR,
		CASE WHEN (mdi.STANDARD_AUDIT_DATE = '') THEN NULL
			ELSE to_date(mdi.STANDARD_AUDIT_DATE, 'YYYY.MM.DD')
		END STANDARD_AUDIT_DATE,
		CASE WHEN (mdi.CA_OWNER_OR_CERT_NAME = '') THEN NULL
			ELSE mdi.CA_OWNER_OR_CERT_NAME
		END CA_OWNER_OR_CERT_NAME,
		CASE WHEN (mdi.ISSUER_CN = '') THEN NULL
			ELSE mdi.ISSUER_CN
		END ISSUER_CN,
		CASE WHEN (mdi.ISSUER_O = '') THEN NULL
			ELSE mdi.ISSUER_O
		END ISSUER_O,
		CASE WHEN (mdi.SUBJECT_CN = '') THEN NULL
			ELSE mdi.SUBJECT_CN
		END SUBJECT_CN,
		CASE WHEN (mdi.SUBJECT_O = '') THEN NULL
			ELSE mdi.SUBJECT_O
		END SUBJECT_O,
		decode(replace(mdi.CERT_SHA1, ':', ''), 'hex') CERT_SHA1,
		'Disclosed'::disclosure_status_type	DISCLOSURE_STATUS
	FROM mozilla_disclosure_import mdi
		LEFT OUTER JOIN certificate c ON (decode(replace(mdi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1'))
	WHERE mdi.RECORD_TYPE != 'Owner';

CREATE TABLE mozilla_revoked_disclosure_import (
	CA_OWNER				text,
	REVOCATION_STATUS		text,
	REASON_CODE				text,
	REVOCATION_DATE			text,
	CA_OWNER_OR_CERT_NAME	text,
	ISSUER_CN				text,
	ISSUER_O				text,
	SUBJECT_CN				text,
	SUBJECT_O				text,
	CERT_SHA1				text,
	VALID_FROM_GMT			text,
	VALID_TO_GMT			text,
	SIGNING_KEY_PARAMETERS	text,
	SIGNATURE_ALGORITHM		text
);

\COPY mozilla_revoked_disclosure_import FROM 'mozilla_revoked_disclosures.csv' CSV HEADER;

INSERT INTO mozilla_disclosure_temp (
		CERTIFICATE_ID, PARENT_CERTIFICATE_ID, RECORD_TYPE,
		CA_OWNER_OR_CERT_NAME,
		ISSUER_CN,
		ISSUER_O,
		SUBJECT_CN,
		SUBJECT_O,
		CERT_SHA1,
		DISCLOSURE_STATUS
	)
	SELECT c.ID, NULL, 'Revoked',
			CASE WHEN (mrdi.CA_OWNER_OR_CERT_NAME = '') THEN NULL
				ELSE mrdi.CA_OWNER_OR_CERT_NAME
			END,
			CASE WHEN (mrdi.ISSUER_CN = '') THEN NULL
				ELSE mrdi.ISSUER_CN
			END,
			CASE WHEN (mrdi.ISSUER_O = '') THEN NULL
				ELSE mrdi.ISSUER_O
			END,
			CASE WHEN (mrdi.SUBJECT_CN = '') THEN NULL
				ELSE mrdi.SUBJECT_CN
			END,
			CASE WHEN (mrdi.SUBJECT_O = '') THEN NULL
				ELSE mrdi.SUBJECT_O
			END,
			decode(replace(mrdi.CERT_SHA1, ':', ''), 'hex'),
			'Revoked'
		FROM mozilla_revoked_disclosure_import mrdi
			LEFT OUTER JOIN certificate c ON (decode(replace(mrdi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1'));

/* Look for the issuer, prioritizing Disclosed Root CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent, mozilla_disclosure_temp mdt_parent
	WHERE mdt.CP_CPS_SAME_AS_PARENT
		AND mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND c_parent.ISSUER_CA_ID = c.ISSUER_CA_ID
		AND c_parent.ID = mdt_parent.CERTIFICATE_ID;
/* ...then Disclosed Intermediate CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = coalesce(mdt.PARENT_CERTIFICATE_ID, cac_parent.CERTIFICATE_ID)
	FROM certificate c, ca_certificate cac_parent, mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
/* ...then any other CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = coalesce(mdt.PARENT_CERTIFICATE_ID, cac_parent.CERTIFICATE_ID)
	FROM certificate c, ca_certificate cac_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID;

/* Handle CP/CPS inheritance.  Repeat several times, to populate several levels of Sub-CA */
UPDATE mozilla_disclosure_temp mdt
	SET CP_URL = coalesce(mdt.CP_URL, mdt_parent.CP_URL),
		CPS_URL = coalesce(mdt.CPS_URL, mdt_parent.CPS_URL)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CP_CPS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET CP_URL = coalesce(mdt.CP_URL, mdt_parent.CP_URL),
		CPS_URL = coalesce(mdt.CPS_URL, mdt_parent.CPS_URL)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CP_CPS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET CP_URL = coalesce(mdt.CP_URL, mdt_parent.CP_URL),
		CPS_URL = coalesce(mdt.CPS_URL, mdt_parent.CPS_URL)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CP_CPS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET CP_URL = coalesce(mdt.CP_URL, mdt_parent.CP_URL),
		CPS_URL = coalesce(mdt.CPS_URL, mdt_parent.CPS_URL)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CP_CPS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;

/* Handle inheritance of audit details.  Repeat several times, to populate several levels of Sub-CA */
UPDATE mozilla_disclosure_temp mdt
	SET STANDARD_AUDIT_URL = coalesce(mdt.STANDARD_AUDIT_URL, mdt_parent.STANDARD_AUDIT_URL),
		BR_AUDIT_URL = coalesce(mdt.BR_AUDIT_URL, mdt_parent.BR_AUDIT_URL),
		AUDITOR = coalesce(mdt.AUDITOR, mdt_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(mdt.STANDARD_AUDIT_DATE, mdt_parent.STANDARD_AUDIT_DATE)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.AUDITS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET STANDARD_AUDIT_URL = coalesce(mdt.STANDARD_AUDIT_URL, mdt_parent.STANDARD_AUDIT_URL),
		BR_AUDIT_URL = coalesce(mdt.BR_AUDIT_URL, mdt_parent.BR_AUDIT_URL),
		AUDITOR = coalesce(mdt.AUDITOR, mdt_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(mdt.STANDARD_AUDIT_DATE, mdt_parent.STANDARD_AUDIT_DATE)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.AUDITS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET STANDARD_AUDIT_URL = coalesce(mdt.STANDARD_AUDIT_URL, mdt_parent.STANDARD_AUDIT_URL),
		BR_AUDIT_URL = coalesce(mdt.BR_AUDIT_URL, mdt_parent.BR_AUDIT_URL),
		AUDITOR = coalesce(mdt.AUDITOR, mdt_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(mdt.STANDARD_AUDIT_DATE, mdt_parent.STANDARD_AUDIT_DATE)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.AUDITS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;
UPDATE mozilla_disclosure_temp mdt
	SET STANDARD_AUDIT_URL = coalesce(mdt.STANDARD_AUDIT_URL, mdt_parent.STANDARD_AUDIT_URL),
		BR_AUDIT_URL = coalesce(mdt.BR_AUDIT_URL, mdt_parent.BR_AUDIT_URL),
		AUDITOR = coalesce(mdt.AUDITOR, mdt_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(mdt.STANDARD_AUDIT_DATE, mdt_parent.STANDARD_AUDIT_DATE)
	FROM mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.AUDITS_SAME_AS_PARENT
		AND mdt.PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID;

ALTER TABLE mozilla_disclosure_temp DROP COLUMN CP_CPS_SAME_AS_PARENT;

ALTER TABLE mozilla_disclosure_temp DROP COLUMN AUDITS_SAME_AS_PARENT;

CREATE INDEX md_c_temp
	ON mozilla_disclosure_temp (CERTIFICATE_ID);

CREATE INDEX md_ds_c_temp
	ON mozilla_disclosure_temp (DISCLOSURE_STATUS, CERTIFICATE_ID);

INSERT INTO mozilla_disclosure_temp (
		CERTIFICATE_ID, CA_OWNER_OR_CERT_NAME,
		ISSUER_O,
		ISSUER_CN,
		SUBJECT_O,
		SUBJECT_CN,
		CERT_SHA1, DISCLOSURE_STATUS
	)
	SELECT c.ID, get_ca_name_attribute(cac.CA_ID),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName'),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName'),
			get_ca_name_attribute(cac.CA_ID, 'organizationName'),
			get_ca_name_attribute(cac.CA_ID, 'commonName'),
			digest(c.CERTIFICATE, 'sha1'), 'Undisclosed'
		FROM ca, ca_certificate cac, certificate c
		WHERE ca.LINTING_APPLIES
			AND ca.ID = cac.CA_ID
			AND cac.CERTIFICATE_ID = c.ID
			AND NOT EXISTS (
				SELECT 1
					FROM mozilla_disclosure_temp mdt
					WHERE mdt.CERTIFICATE_ID = c.ID
			);

UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'Expired'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND x509_notAfter(c.CERTIFICATE) < statement_timestamp();

UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);

UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'NoKnownServerAuthTrustPath'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
					AND statement_timestamp() BETWEEN ctp.EARLIEST_NOT_BEFORE
												AND ctp.LATEST_NOT_AFTER
		);


ANALYZE mozilla_disclosure_temp;

GRANT SELECT ON mozilla_disclosure_temp TO httpd;

DROP TABLE mozilla_disclosure_import;

DROP TABLE mozilla_revoked_disclosure_import;

DROP TABLE mozilla_disclosure;

ALTER TABLE mozilla_disclosure_temp RENAME TO mozilla_disclosure;

ALTER INDEX md_c_temp RENAME TO md_c;

ALTER INDEX md_ds_c_temp RENAME TO md_ds_c;
