\timing

\echo Importing Disclosed CA Certificates

CREATE TABLE mozilla_disclosure_manual_import (
	PARENT_CERT_NAME			text,
	CERT_NAME					text,
	ISSUER_CN					text,
	ISSUER_O					text,
	SUBJECT_CN					text,
	SUBJECT_O					text,
	CERT_SHA1					text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	EXTENDED_KEY_USAGE			text,
	CP_CPS_SAME_AS_PARENT		text,
	CP_URL						text,
	CPS_URL						text,
	AUDITS_SAME_AS_PARENT		text,
	STANDARD_AUDIT_URL			text,
	BR_AUDIT_URL				text,
	AUDITOR						text,
	STANDARD_AUDIT_DATE			text,
	MGMT_ASSERTIONS_BY			text,
	CA_OWNER					text
);

\COPY mozilla_disclosure_manual_import FROM 'mozilla_disclosures_manual.csv' CSV HEADER;

CREATE TABLE mozilla_disclosure_import (
	CA_OWNER					text,
	PARENT_NAME					text,
	CERT_NAME					text,
	ISSUER_CN					text,
	ISSUER_O					text,
	SUBJECT_CN					text,
	SUBJECT_O					text,
	SERIAL_NUMBER				text,
	CERT_SHA256					text,
	LOGICAL_CERTIFICATE_ID		text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	EXTENDED_KEY_USAGE			text,
	CP_CPS_SAME_AS_PARENT		text,
	CP_URL						text,
	CPS_URL						text,
	AUDITS_SAME_AS_PARENT		text,
	STANDARD_AUDIT_URL			text,
	BR_AUDIT_URL				text,
	AUDITOR						text,
	STANDARD_AUDIT_DATE			text,
	MGMT_ASSERTIONS_BY			text,
	COMMENTS					text
);

\COPY mozilla_disclosure_import FROM 'mozilla_disclosures.csv' CSV HEADER;

CREATE TABLE mozilla_disclosure_temp AS
SELECT	c.ID	CERTIFICATE_ID,
		mdi.CA_OWNER,
		NULL::integer	PARENT_CERTIFICATE_ID,
		mdi.PARENT_NAME	PARENT_NAME,
		NULL::integer	INCLUDED_CERTIFICATE_ID,
		NULL::text		INCLUDED_CERTIFICATE_OWNER,
		'Intermediate'::text	RECORD_TYPE,
		regexp_replace(replace(mdmi.CERT_NAME, '<a href="', ''), '".*$', '')	SALESFORCE_ID,
		CASE WHEN (mdi.CP_CPS_SAME_AS_PARENT = '') THEN FALSE
			ELSE (mdi.CP_CPS_SAME_AS_PARENT = 'TRUE')
		END CP_CPS_SAME_AS_PARENT,
		CASE WHEN (mdi.CP_URL = '') THEN NULL
			ELSE mdi.CP_URL
		END CP_URL,
		CASE WHEN (mdi.CPS_URL = '') THEN NULL
			ELSE mdi.CPS_URL
		END CPS_URL,
		CASE WHEN (mdi.AUDITS_SAME_AS_PARENT = '') THEN FALSE
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
		CASE WHEN (mdi.CERT_NAME = '') THEN NULL
			ELSE mdi.CERT_NAME
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
		decode(replace(mdi.CERT_SHA256, ':', ''), 'hex') CERT_SHA256,
		'Disclosed'::disclosure_status_type	DISCLOSURE_STATUS
	FROM mozilla_disclosure_import mdi
		LEFT OUTER JOIN certificate c ON (decode(replace(mdi.CERT_SHA256, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha256'))
		LEFT OUTER JOIN mozilla_disclosure_manual_import mdmi ON (
			decode(replace(mdmi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1')
			AND mdi.PARENT_NAME = mdmi.PARENT_CERT_NAME
		);


\echo Importing Revoked Intermediate Certificates

CREATE TABLE mozilla_revoked_disclosure_manual_import (
	REVOCATION_STATUS			text,
	REASON_CODE					text,
	REVOCATION_DATE				text,
	CERT_NAME					text,
	ISSUER_CN					text,
	ISSUER_O					text,
	SUBJECT_CN					text,
	SUBJECT_O					text,
	CERT_SHA1					text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	CA_OWNER					text
);

\COPY mozilla_revoked_disclosure_manual_import FROM 'mozilla_revoked_disclosures_manual.csv' CSV HEADER;

CREATE TABLE mozilla_revoked_disclosure_import (
	CA_OWNER					text,
	REVOCATION_STATUS			text,
	REASON_CODE					text,
	REVOCATION_DATE				text,
	ONECRL_STATUS				text,
	SERIAL_NUMBER				text,
	CA_OWNER_OR_CERT_NAME		text,
	ISSUER_CN					text,
	ISSUER_O					text,
	SUBJECT_CN					text,
	SUBJECT_O					text,
	CERT_SHA256					text,
	LOGICAL_CERTIFICATE_ID		text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	CRL_URL						text,
	ALTERNATE_CRL				text,
	OCSP_URL					text,
	COMMENTS					text
);

\COPY mozilla_revoked_disclosure_import FROM 'mozilla_revoked_disclosures.csv' CSV HEADER;

INSERT INTO mozilla_disclosure_temp (
		CERTIFICATE_ID, CA_OWNER, PARENT_CERTIFICATE_ID, RECORD_TYPE,
		SALESFORCE_ID,
		CA_OWNER_OR_CERT_NAME,
		ISSUER_CN,
		ISSUER_O,
		SUBJECT_CN,
		SUBJECT_O,
		CERT_SHA256,
		DISCLOSURE_STATUS
	)
	SELECT c.ID, mrdi.CA_OWNER, NULL, 'Revoked',
			regexp_replace(replace(mrdmi.CERT_NAME, '<a href="', ''), '".*$', '')	SALESFORCE_ID,
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
			decode(replace(mrdi.CERT_SHA256, ':', ''), 'hex'),
			'Revoked'
		FROM mozilla_revoked_disclosure_import mrdi
			LEFT OUTER JOIN certificate c ON (decode(replace(mrdi.CERT_SHA256, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha256'))
			LEFT OUTER JOIN mozilla_revoked_disclosure_manual_import mrdmi ON (decode(replace(mrdmi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1'));


\echo Importing Included CA Certificates

CREATE TABLE mozilla_included_manual_import (
	ISSUER_O					text,
	CERT_NAME					text,
	CERT_SHA1					text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	CP_URL						text,
	CPS_URL						text,
	STANDARD_AUDIT_URL			text,
	BR_AUDIT_URL				text,
	AUDITOR						text,
	STANDARD_AUDIT_DATE			text,
	MGMT_ASSERTIONS_BY			text,
	CA_OWNER					text
);

\COPY mozilla_included_manual_import FROM 'mozilla_included_manual.csv' CSV HEADER;

CREATE TABLE mozilla_included_import (
	CA_OWNER					text,
	ISSUER_O					text,
	ISSUER_OU					text,
	CN_OR_CERT_NAME				text,
	SERIAL_NUMBER				text,
	CERT_SHA256					text,
	LOGICAL_CERTIFICATE_ID		text,
	VALID_FROM_GMT				text,
	VALID_TO_GMT				text,
	PUBLIC_KEY_ALGORITHM		text,
	SIGNATURE_HASH_ALGORITHM	text,
	TRUST_BITS					text,
	EV_POLICY_OIDS				text,
	APPROVAL_BUG				text,
	FIRST_NSS_RELEASE			text,
	FIRST_FIREFOX_RELEASE		text,
	TEST_URL					text,
	MOZILLA_CONSTRAINTS			text,
	COMPANY_WEBSITE				text,
	GEOGRAPHIC_FOCUS			text,
	CP_URL						text,
	CPS_URL						text,
	STANDARD_AUDIT_URL			text,
	BR_AUDIT_URL				text,
	EV_AUDIT_URL				text,
	AUDITOR						text,
	STANDARD_AUDIT_TYPE			text,
	STANDARD_AUDIT_DATE			text
);

\COPY mozilla_included_import FROM 'mozilla_included.csv' CSV HEADER;

INSERT INTO mozilla_disclosure_temp (
		CERTIFICATE_ID, CA_OWNER, PARENT_CERTIFICATE_ID, RECORD_TYPE,
		SALESFORCE_ID,
		CP_CPS_SAME_AS_PARENT,
		CP_URL,
		CPS_URL,
		AUDITS_SAME_AS_PARENT,
		STANDARD_AUDIT_URL,
		BR_AUDIT_URL,
		AUDITOR,
		STANDARD_AUDIT_DATE,
		CA_OWNER_OR_CERT_NAME,
		ISSUER_CN,
		ISSUER_O,
		SUBJECT_CN,
		SUBJECT_O,
		CERT_SHA256,
		DISCLOSURE_STATUS
	)
	SELECT c.ID, mii.CA_OWNER, NULL, 'Root',
			regexp_replace(replace(mimi.CERT_NAME, '<a href="', ''), '".*$', ''),
			FALSE,
			CASE WHEN (mii.CP_URL = '') THEN NULL
				ELSE mii.CP_URL
			END CP_URL,
			CASE WHEN (mii.CPS_URL = '') THEN NULL
				ELSE mii.CPS_URL
			END CPS_URL,
			FALSE,
			CASE WHEN (mii.STANDARD_AUDIT_URL = '') THEN NULL
				ELSE mii.STANDARD_AUDIT_URL
			END STANDARD_AUDIT_URL,
			CASE WHEN (mii.BR_AUDIT_URL = '') THEN NULL
				ELSE mii.BR_AUDIT_URL
			END BR_AUDIT_URL,
			CASE WHEN (mii.AUDITOR = '') THEN NULL
				ELSE mii.AUDITOR
			END AUDITOR,
			CASE WHEN (mii.STANDARD_AUDIT_DATE = '') THEN NULL
				ELSE to_date(mii.STANDARD_AUDIT_DATE, 'YYYY.MM.DD')
			END STANDARD_AUDIT_DATE,
			CASE WHEN (mii.CN_OR_CERT_NAME = '') THEN NULL
				ELSE mii.CN_OR_CERT_NAME
			END,
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', FALSE) LIMIT 1),
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', FALSE) LIMIT 1),
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) LIMIT 1),
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) LIMIT 1),
			decode(replace(mii.CERT_SHA256, ':', ''), 'hex'),
			'Disclosed'
		FROM mozilla_included_import mii
			LEFT OUTER JOIN certificate c ON (decode(replace(mii.CERT_SHA256, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha256'))
			LEFT OUTER JOIN mozilla_included_manual_import mimi ON (decode(replace(mimi.CERT_SHA1, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha1'));


\echo Finding All CA Certificates
INSERT INTO mozilla_disclosure_temp (
		CERTIFICATE_ID, CA_OWNER_OR_CERT_NAME,
		ISSUER_O,
		ISSUER_CN,
		SUBJECT_O,
		SUBJECT_CN,
		CERT_SHA256, DISCLOSURE_STATUS
	)
	SELECT c.ID, get_ca_name_attribute(cac.CA_ID),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName'),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName'),
			get_ca_name_attribute(cac.CA_ID, 'organizationName'),
			get_ca_name_attribute(cac.CA_ID, 'commonName'),
			digest(c.CERTIFICATE, 'sha256'), 'Undisclosed'
		FROM ca, ca_certificate cac, certificate c
		WHERE ca.LINTING_APPLIES
			AND ca.ID = cac.CA_ID
			AND cac.CERTIFICATE_ID = c.ID
			AND NOT EXISTS (
				SELECT 1
					FROM mozilla_disclosure_temp mdt
					WHERE mdt.CERTIFICATE_ID = c.ID
			);


\echo Determining Parent CA Certificates

/* Look for the issuer, prioritizing Disclosed Root CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent, mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND c_parent.ID = mdt_parent.CERTIFICATE_ID
		AND mdt_parent.RECORD_TYPE = 'Root';
/* ...then Disclosed Intermediate CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, mozilla_disclosure_temp mdt_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.PARENT_CERTIFICATE_ID IS NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = mdt_parent.CERTIFICATE_ID
		AND mdt_parent.RECORD_TYPE IS NOT NULL;
/* ...then any other CA certs trusted by Mozilla... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = (
		SELECT c_parent.ID
			FROM certificate c, ca_certificate cac_parent, certificate c_parent, ca_trust_purpose ctp
			WHERE mdt.CERTIFICATE_ID = c.ID
				AND c.ISSUER_CA_ID = cac_parent.CA_ID
				AND cac_parent.CERTIFICATE_ID = c_parent.ID
				AND c.ID != c_parent.ID
				AND c_parent.ISSUER_CA_ID = ctp.CA_ID
				AND ctp.TRUST_CONTEXT_ID = 5
			ORDER BY ctp.IS_TIME_VALID DESC,
					ctp.SHORTEST_CHAIN,
					ctp.TRUST_PURPOSE_ID
			LIMIT 1
	)
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.PARENT_CERTIFICATE_ID IS NULL;
/* ...then any other CA certs... */
UPDATE mozilla_disclosure_temp mdt
	SET PARENT_CERTIFICATE_ID = cac_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent
	WHERE mdt.CERTIFICATE_ID IS NOT NULL
		AND mdt.PARENT_CERTIFICATE_ID IS NULL
		AND mdt.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID;


/* Special case for 'Root' records, because some included certificates are not self-signed */
\echo Find Included Certificates / Owners
UPDATE mozilla_disclosure_temp mdt
	SET INCLUDED_CERTIFICATE_ID = mdt.CERTIFICATE_ID,
		INCLUDED_CERTIFICATE_OWNER = mdt.CA_OWNER
	WHERE mdt.RECORD_TYPE = 'Root';
UPDATE mozilla_disclosure_temp mdt1
	SET INCLUDED_CERTIFICATE_ID = mdt10.CERTIFICATE_ID,
		INCLUDED_CERTIFICATE_OWNER = mdt10.CA_OWNER
	FROM mozilla_disclosure_temp mdt2
		LEFT OUTER JOIN mozilla_disclosure_temp mdt3 ON (mdt2.PARENT_CERTIFICATE_ID = mdt3.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt4 ON (mdt3.PARENT_CERTIFICATE_ID = mdt4.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt5 ON (mdt4.PARENT_CERTIFICATE_ID = mdt5.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt6 ON (mdt5.PARENT_CERTIFICATE_ID = mdt6.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt7 ON (mdt6.PARENT_CERTIFICATE_ID = mdt7.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt8 ON (mdt7.PARENT_CERTIFICATE_ID = mdt8.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt9 ON (mdt8.PARENT_CERTIFICATE_ID = mdt9.CERTIFICATE_ID)
		LEFT OUTER JOIN mozilla_disclosure_temp mdt10 ON (mdt9.PARENT_CERTIFICATE_ID = mdt10.CERTIFICATE_ID)
	WHERE mdt1.INCLUDED_CERTIFICATE_ID IS NULL
		AND mdt1.PARENT_CERTIFICATE_ID = mdt2.CERTIFICATE_ID
		AND mdt10.RECORD_TYPE IS NOT NULL;


/* Handle CP/CPS inheritance.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling CP/CPS Inheritance
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
\echo Handling Audit Inheritance
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


\echo Creating Some Indexes

CREATE INDEX md_c_temp
	ON mozilla_disclosure_temp (CERTIFICATE_ID);

CREATE INDEX md_ds_c_temp
	ON mozilla_disclosure_temp (DISCLOSURE_STATUS, CERTIFICATE_ID);


\echo Disclosed, Revoked -> Revoked via OneCRL
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'RevokedViaOneCRL'
	FROM mozilla_onecrl m
	WHERE mdt.DISCLOSURE_STATUS IN ('Disclosed', 'Revoked')
		AND mdt.CERTIFICATE_ID = m.CERTIFICATE_ID;

\echo Disclosed -> DisclosureIncomplete
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'DisclosureIncomplete'
	WHERE mdt.DISCLOSURE_STATUS = 'Disclosed'
		AND (
			(
				NOT mdt.CP_CPS_SAME_AS_PARENT
				AND (coalesce(mdt.CP_URL, mdt.CPS_URL) IS NULL)
			)
			OR (
				NOT mdt.AUDITS_SAME_AS_PARENT
				AND (coalesce(mdt.STANDARD_AUDIT_URL, mdt.BR_AUDIT_URL) IS NULL)
			)
		);

\echo Disclosed -> DisclosedWithErrors
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Disclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND (mdt.PARENT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (mdt.PARENT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');

\echo Undisclosed -> Expired
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'Expired'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND x509_notAfter(c.CERTIFICATE) < statement_timestamp();

\echo Undisclosed -> TechnicallyConstrained
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);

\echo Undisclosed -> NoKnownServerAuthTrustPath
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
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
		);

\echo Undisclosed -> AllServerAuthPathsRevoked
UPDATE mozilla_disclosure_temp mdt
	SET DISCLOSURE_STATUS = 'AllServerAuthPathsRevoked'
	FROM certificate c
	WHERE mdt.DISCLOSURE_STATUS = 'Undisclosed'
		AND mdt.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);


\echo Tidying Up

ANALYZE mozilla_disclosure_temp;

GRANT SELECT ON mozilla_disclosure_temp TO httpd;

DROP TABLE mozilla_disclosure_import;

DROP TABLE mozilla_disclosure_manual_import;

DROP TABLE mozilla_revoked_disclosure_import;

DROP TABLE mozilla_revoked_disclosure_manual_import;

DROP TABLE mozilla_included_import;

DROP TABLE mozilla_included_manual_import;

DROP TABLE mozilla_disclosure;

ALTER TABLE mozilla_disclosure_temp RENAME TO mozilla_disclosure;

ALTER INDEX md_c_temp RENAME TO md_c;

ALTER INDEX md_ds_c_temp RENAME TO md_ds_c;

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-disclosures,0}'::text[]), 1, 6);
