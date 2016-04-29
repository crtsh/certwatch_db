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
		mdi.CA_OWNER_OR_CERT_NAME,
		decode(replace(mdi.CERT_SHA1, ':', ''), 'hex') CERT_SHA1
	FROM mozilla_disclosure_import mdi
		LEFT OUTER JOIN certificate c ON (decode(replace(mdi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1'))
	WHERE mdi.RECORD_TYPE != 'Owner';

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

ANALYZE mozilla_disclosure_temp;

GRANT SELECT ON mozilla_disclosure_temp TO httpd;

DROP TABLE mozilla_disclosure_import;

DROP TABLE mozilla_disclosure;

ALTER TABLE mozilla_disclosure_temp RENAME TO mozilla_disclosure;
