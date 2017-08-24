\timing

\echo Importing All CCADB Certificate Records

CREATE TABLE ccadb_certificate_import (
	SALESFORCE_ID				text,
	CA_OWNER					text,
	CERT_NAME					text,
	PARENT_CERT_NAME			text,
	CERT_RECORD_TYPE			text,
	REVOCATION_STATUS			text,
	CERT_SHA256					text,
	AUDITS_SAME_AS_PARENT		text,
	AUDITOR						text,
	STANDARD_AUDIT_URL			text,
	STANDARD_AUDIT_TYPE			text,
	STANDARD_AUDIT_DATE			text,
	STANDARD_AUDIT_START		text,
	STANDARD_AUDIT_END			text,
	BRSSL_AUDIT_URL				text,
	BRSSL_AUDIT_TYPE			text,
	BRSSL_AUDIT_DATE			text,
	BRSSL_AUDIT_START			text,
	BRSSL_AUDIT_END				text,
	EVSSL_AUDIT_URL				text,
	EVSSL_AUDIT_TYPE			text,
	EVSSL_AUDIT_DATE			text,
	EVSSL_AUDIT_START			text,
	EVSSL_AUDIT_END				text,
	EVCODE_AUDIT_URL			text,
	EVCODE_AUDIT_TYPE			text,
	EVCODE_AUDIT_DATE			text,
	EVCODE_AUDIT_START			text,
	EVCODE_AUDIT_END			text,
	CP_CPS_SAME_AS_PARENT		text,
	CP_URL						text,
	CPS_URL						text,
	TEST_WEBSITE_VALID			text,
	TEST_WEBSITE_EXPIRED		text,
	TEST_WEBSITE_REVOKED		text,
	IS_TECHNICALLY_CONSTRAINED	text,
	MOZILLA_STATUS				text,
	MICROSOFT_STATUS			text
);

\COPY ccadb_certificate_import FROM 'ccadb_all_certificate_records.csv' CSV HEADER;

CREATE TABLE ccadb_certificate_temp AS
SELECT	c.ID					CERTIFICATE_ID,
		NULL::integer			PARENT_CERTIFICATE_ID,
		NULL::integer			INCLUDED_CERTIFICATE_ID,
		NULL::text				INCLUDED_CERTIFICATE_OWNER,
		cci.SALESFORCE_ID,
		cci.CA_OWNER,
		CASE WHEN (cci.CERT_NAME = '') THEN NULL
			ELSE cci.CERT_NAME
		END CERT_NAME,
		CASE WHEN (cci.PARENT_CERT_NAME = '') THEN NULL
			ELSE cci.PARENT_CERT_NAME
		END PARENT_CERT_NAME,
		cci.CERT_RECORD_TYPE,
		cci.REVOCATION_STATUS,
		decode(replace(cci.CERT_SHA256, ':', ''), 'hex')	CERT_SHA256,
		CASE WHEN (cci.AUDITS_SAME_AS_PARENT = '') THEN FALSE
			ELSE (lower(cci.AUDITS_SAME_AS_PARENT) = 'true')
		END AUDITS_SAME_AS_PARENT,
		CASE WHEN (cci.AUDITOR = '') THEN NULL
			ELSE cci.AUDITOR
		END AUDITOR,
		CASE WHEN (cci.STANDARD_AUDIT_URL = '') THEN NULL
			ELSE cci.STANDARD_AUDIT_URL
		END STANDARD_AUDIT_URL,
		CASE WHEN (cci.STANDARD_AUDIT_TYPE = '') THEN NULL
			ELSE cci.STANDARD_AUDIT_TYPE
		END STANDARD_AUDIT_TYPE,
		CASE WHEN (cci.STANDARD_AUDIT_DATE = '') THEN NULL
			ELSE to_date(cci.STANDARD_AUDIT_DATE, 'YYYY.MM.DD')
		END STANDARD_AUDIT_DATE,
		CASE WHEN (cci.STANDARD_AUDIT_START = '') THEN NULL
			ELSE to_date(cci.STANDARD_AUDIT_START, 'YYYY.MM.DD')
		END STANDARD_AUDIT_START,
		CASE WHEN (cci.STANDARD_AUDIT_END = '') THEN NULL
			ELSE to_date(cci.STANDARD_AUDIT_END, 'YYYY.MM.DD')
		END STANDARD_AUDIT_END,
		CASE WHEN (cci.BRSSL_AUDIT_URL = '') THEN NULL
			ELSE cci.BRSSL_AUDIT_URL
		END BRSSL_AUDIT_URL,
		CASE WHEN (cci.BRSSL_AUDIT_TYPE = '') THEN NULL
			ELSE cci.BRSSL_AUDIT_TYPE
		END BRSSL_AUDIT_TYPE,
		CASE WHEN (cci.BRSSL_AUDIT_DATE = '') THEN NULL
			ELSE to_date(cci.BRSSL_AUDIT_DATE, 'YYYY.MM.DD')
		END BRSSL_AUDIT_DATE,
		CASE WHEN (cci.BRSSL_AUDIT_START = '') THEN NULL
			ELSE to_date(cci.BRSSL_AUDIT_START, 'YYYY.MM.DD')
		END BRSSL_AUDIT_START,
		CASE WHEN (cci.BRSSL_AUDIT_END = '') THEN NULL
			ELSE to_date(cci.BRSSL_AUDIT_END, 'YYYY.MM.DD')
		END BRSSL_AUDIT_END,
		CASE WHEN (cci.EVSSL_AUDIT_URL = '') THEN NULL
			ELSE cci.EVSSL_AUDIT_URL
		END EVSSL_AUDIT_URL,
		CASE WHEN (cci.EVSSL_AUDIT_TYPE = '') THEN NULL
			ELSE cci.EVSSL_AUDIT_TYPE
		END EVSSL_AUDIT_TYPE,
		CASE WHEN (cci.EVSSL_AUDIT_DATE = '') THEN NULL
			ELSE to_date(cci.EVSSL_AUDIT_DATE, 'YYYY.MM.DD')
		END EVSSL_AUDIT_DATE,
		CASE WHEN (cci.EVSSL_AUDIT_START = '') THEN NULL
			ELSE to_date(cci.EVSSL_AUDIT_START, 'YYYY.MM.DD')
		END EVSSL_AUDIT_START,
		CASE WHEN (cci.EVSSL_AUDIT_END = '') THEN NULL
			ELSE to_date(cci.EVSSL_AUDIT_END, 'YYYY.MM.DD')
		END EVSSL_AUDIT_END,
		CASE WHEN (cci.EVCODE_AUDIT_URL = '') THEN NULL
			ELSE cci.EVCODE_AUDIT_URL
		END EVCODE_AUDIT_URL,
		CASE WHEN (cci.EVCODE_AUDIT_TYPE = '') THEN NULL
			ELSE cci.EVCODE_AUDIT_TYPE
		END EVCODE_AUDIT_TYPE,
		CASE WHEN (cci.EVCODE_AUDIT_DATE = '') THEN NULL
			ELSE to_date(cci.EVCODE_AUDIT_DATE, 'YYYY.MM.DD')
		END EVCODE_AUDIT_DATE,
		CASE WHEN (cci.EVCODE_AUDIT_START = '') THEN NULL
			ELSE to_date(cci.EVCODE_AUDIT_START, 'YYYY.MM.DD')
		END EVCODE_AUDIT_START,
		CASE WHEN (cci.EVCODE_AUDIT_END = '') THEN NULL
			ELSE to_date(cci.EVCODE_AUDIT_END, 'YYYY.MM.DD')
		END EVCODE_AUDIT_END,
		CASE WHEN (cci.CP_CPS_SAME_AS_PARENT = '') THEN FALSE
			ELSE (lower(cci.CP_CPS_SAME_AS_PARENT) = 'true')
		END CP_CPS_SAME_AS_PARENT,
		CASE WHEN (cci.CP_URL = '') THEN NULL
			ELSE cci.CP_URL
		END CP_URL,
		CASE WHEN (cci.CPS_URL = '') THEN NULL
			ELSE cci.CPS_URL
		END CPS_URL,
		cci.TEST_WEBSITE_VALID,
		cci.TEST_WEBSITE_EXPIRED,
		cci.TEST_WEBSITE_REVOKED,
		cci.IS_TECHNICALLY_CONSTRAINED,
		cci.MOZILLA_STATUS,
		cci.MICROSOFT_STATUS,
		(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', FALSE) LIMIT 1)		ISSUER_CN,
		(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', FALSE) LIMIT 1)	ISSUER_O,
		(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) LIMIT 1)			SUBJECT_CN,
		(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) LIMIT 1)	SUBJECT_O,
		CASE cci.REVOCATION_STATUS
			WHEN 'Revoked' THEN 'Revoked'::disclosure_status_type
			WHEN 'Parent Cert Revoked' THEN 'ParentRevoked'::disclosure_status_type
			ELSE 'Disclosed'::disclosure_status_type
		END DISCLOSURE_STATUS,
		statement_timestamp()	LAST_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate_import cci
		LEFT OUTER JOIN certificate c ON (decode(replace(cci.CERT_SHA256, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha256'));


\echo Finding All CA Certificates
INSERT INTO ccadb_certificate_temp (
		CERTIFICATE_ID, CERT_NAME,
		ISSUER_O,
		ISSUER_CN,
		SUBJECT_O,
		SUBJECT_CN,
		CERT_SHA256, DISCLOSURE_STATUS,
		LAST_DISCLOSURE_STATUS_CHANGE
	)
	SELECT c.ID, get_ca_name_attribute(cac.CA_ID),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName'),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName'),
			get_ca_name_attribute(cac.CA_ID, 'organizationName'),
			get_ca_name_attribute(cac.CA_ID, 'commonName'),
			digest(c.CERTIFICATE, 'sha256'), 'Undisclosed',
			statement_timestamp()
		FROM ca, ca_certificate cac, certificate c
		WHERE ca.LINTING_APPLIES
			AND ca.ID = cac.CA_ID
			AND cac.CERTIFICATE_ID = c.ID
			AND NOT EXISTS (
				SELECT 1
					FROM ccadb_certificate_temp cct
					WHERE cct.CERTIFICATE_ID = c.ID
			);


\echo Determining Parent CA Certificates

/* Look for the issuer, prioritizing Disclosed Root CA certs... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent, ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND c_parent.ID = cct_parent.CERTIFICATE_ID
		AND cct_parent.CERT_RECORD_TYPE = 'Root Certificate';
/* ...then Disclosed Intermediate CA certs... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = cct_parent.CERTIFICATE_ID
		AND cct_parent.CERT_RECORD_TYPE IS NOT NULL;
/* ...then any other CA certs trusted by Mozilla... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = (
		SELECT c_parent.ID
			FROM certificate c, ca_certificate cac_parent, certificate c_parent, ca_trust_purpose ctp
			WHERE cct.CERTIFICATE_ID = c.ID
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
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL;
/* ...or by Microsoft... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = (
		SELECT c_parent.ID
			FROM certificate c, ca_certificate cac_parent, certificate c_parent, ca_trust_purpose ctp
			WHERE cct.CERTIFICATE_ID = c.ID
				AND c.ISSUER_CA_ID = cac_parent.CA_ID
				AND cac_parent.CERTIFICATE_ID = c_parent.ID
				AND c.ID != c_parent.ID
				AND c_parent.ISSUER_CA_ID = ctp.CA_ID
				AND ctp.TRUST_CONTEXT_ID = 1
			ORDER BY ctp.IS_TIME_VALID DESC,
					ctp.SHORTEST_CHAIN,
					ctp.TRUST_PURPOSE_ID
			LIMIT 1
	)
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL;
/* ...then any other CA certs... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = cac_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID;


/* Special case for 'Root Certificate' records, because some included certificates are not self-signed */
\echo Find Included Certificates / Owners
UPDATE ccadb_certificate_temp cct
	SET INCLUDED_CERTIFICATE_ID = cct.CERTIFICATE_ID,
		INCLUDED_CERTIFICATE_OWNER = cct.CA_OWNER
	WHERE cct.CERT_RECORD_TYPE = 'Root Certificate';
UPDATE ccadb_certificate_temp cct1
	SET INCLUDED_CERTIFICATE_ID = cct10.CERTIFICATE_ID,
		INCLUDED_CERTIFICATE_OWNER = cct10.CA_OWNER
	FROM ccadb_certificate_temp cct2
		LEFT OUTER JOIN ccadb_certificate_temp cct3 ON (cct2.PARENT_CERTIFICATE_ID = cct3.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct4 ON (cct3.PARENT_CERTIFICATE_ID = cct4.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct5 ON (cct4.PARENT_CERTIFICATE_ID = cct5.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct6 ON (cct5.PARENT_CERTIFICATE_ID = cct6.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct7 ON (cct6.PARENT_CERTIFICATE_ID = cct7.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct8 ON (cct7.PARENT_CERTIFICATE_ID = cct8.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct9 ON (cct8.PARENT_CERTIFICATE_ID = cct9.CERTIFICATE_ID)
		LEFT OUTER JOIN ccadb_certificate_temp cct10 ON (cct9.PARENT_CERTIFICATE_ID = cct10.CERTIFICATE_ID)
	WHERE cct1.INCLUDED_CERTIFICATE_ID IS NULL
		AND cct1.PARENT_CERTIFICATE_ID = cct2.CERTIFICATE_ID
		AND cct10.CERT_RECORD_TYPE IS NOT NULL;


/* Handle CP/CPS inheritance.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling CP/CPS Inheritance
UPDATE ccadb_certificate_temp cct
	SET CP_URL = coalesce(cct.CP_URL, cct_parent.CP_URL),
		CPS_URL = coalesce(cct.CPS_URL, cct_parent.CPS_URL)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CP_CPS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET CP_URL = coalesce(cct.CP_URL, cct_parent.CP_URL),
		CPS_URL = coalesce(cct.CPS_URL, cct_parent.CPS_URL)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CP_CPS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET CP_URL = coalesce(cct.CP_URL, cct_parent.CP_URL),
		CPS_URL = coalesce(cct.CPS_URL, cct_parent.CPS_URL)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CP_CPS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET CP_URL = coalesce(cct.CP_URL, cct_parent.CP_URL),
		CPS_URL = coalesce(cct.CPS_URL, cct_parent.CPS_URL)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CP_CPS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;

/* Handle inheritance of audit details.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling Audit Inheritance
UPDATE ccadb_certificate_temp cct
	SET STANDARD_AUDIT_URL = coalesce(cct.STANDARD_AUDIT_URL, cct_parent.STANDARD_AUDIT_URL),
		BRSSL_AUDIT_URL = coalesce(cct.BRSSL_AUDIT_URL, cct_parent.BRSSL_AUDIT_URL),
		AUDITOR = coalesce(cct.AUDITOR, cct_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(cct.STANDARD_AUDIT_DATE, cct_parent.STANDARD_AUDIT_DATE)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.AUDITS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET STANDARD_AUDIT_URL = coalesce(cct.STANDARD_AUDIT_URL, cct_parent.STANDARD_AUDIT_URL),
		BRSSL_AUDIT_URL = coalesce(cct.BRSSL_AUDIT_URL, cct_parent.BRSSL_AUDIT_URL),
		AUDITOR = coalesce(cct.AUDITOR, cct_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(cct.STANDARD_AUDIT_DATE, cct_parent.STANDARD_AUDIT_DATE)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.AUDITS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET STANDARD_AUDIT_URL = coalesce(cct.STANDARD_AUDIT_URL, cct_parent.STANDARD_AUDIT_URL),
		BRSSL_AUDIT_URL = coalesce(cct.BRSSL_AUDIT_URL, cct_parent.BRSSL_AUDIT_URL),
		AUDITOR = coalesce(cct.AUDITOR, cct_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(cct.STANDARD_AUDIT_DATE, cct_parent.STANDARD_AUDIT_DATE)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.AUDITS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET STANDARD_AUDIT_URL = coalesce(cct.STANDARD_AUDIT_URL, cct_parent.STANDARD_AUDIT_URL),
		BRSSL_AUDIT_URL = coalesce(cct.BRSSL_AUDIT_URL, cct_parent.BRSSL_AUDIT_URL),
		AUDITOR = coalesce(cct.AUDITOR, cct_parent.AUDITOR),
		STANDARD_AUDIT_DATE = coalesce(cct.STANDARD_AUDIT_DATE, cct_parent.STANDARD_AUDIT_DATE)
	FROM ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.AUDITS_SAME_AS_PARENT
		AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;


\echo Creating Some Indexes

CREATE INDEX cc_c_temp
	ON ccadb_certificate_temp (CERTIFICATE_ID);

CREATE INDEX cc_ds_c_temp
	ON ccadb_certificate_temp (DISCLOSURE_STATUS, CERTIFICATE_ID);


\echo Handle the Expired cases
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = CASE DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'Expired'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButExpired'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedButExpired'::disclosure_status_type
			WHEN 'ParentRevoked' THEN 'RevokedButExpired'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.CERTIFICATE_ID = c.ID
		AND x509_notAfter(c.CERTIFICATE) < statement_timestamp();

\echo Undisclosed -> NoKnownServerAuthTrustPath
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'NoKnownServerAuthTrustPath'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
		);

\echo Undisclosed -> AllServerAuthPathsRevoked
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'AllServerAuthPathsRevoked'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);

\echo Handle the OneCRL cases
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = CASE DISCLOSURE_STATUS
			WHEN 'Revoked' THEN 'RevokedViaOneCRL'::disclosure_status_type
			WHEN 'ParentRevoked' THEN 'RevokedViaOneCRL'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButInOneCRL'::disclosure_status_type
		END
	FROM mozilla_onecrl m
	WHERE cct.DISCLOSURE_STATUS IN ('Revoked', 'ParentRevoked', 'Disclosed')
		AND cct.CERTIFICATE_ID = m.CERTIFICATE_ID;

\echo Handle the Technically Constrained cases
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = CASE DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'TechnicallyConstrainedOther'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButConstrained'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS IN ('Undisclosed', 'Disclosed')
		AND coalesce(cct.CERT_RECORD_TYPE, 'Undisclosed') != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);

UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
		AND cct.CERTIFICATE_ID = c.ID
		AND (
			x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
			OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
			OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
		)
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
		);

UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 3
		);

\echo Disclosed -> DisclosedButNoKnownServerAuthTrustPath
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'DisclosedButNoKnownServerAuthTrustPath'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS IN ('Disclosed', 'Revoked', 'ParentRevoked')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND ctp.IS_TIME_VALID
		);

\echo Disclosed -> DisclosureIncomplete
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (
			(
				NOT cct.CP_CPS_SAME_AS_PARENT
				AND (coalesce(cct.CP_URL, cct.CPS_URL) IS NULL)
			)
			OR (
				NOT cct.AUDITS_SAME_AS_PARENT
				AND (coalesce(cct.STANDARD_AUDIT_URL, cct.BRSSL_AUDIT_URL) IS NULL)
			)
		);

\echo Disclosed -> DisclosedWithErrors
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE cct.DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');

\echo Disclosed -> DisclosedButInCRL
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'DisclosedButInCRL'
	FROM certificate c, crl_revoked cr
	WHERE cct.DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID;

\echo DisclosedButInCRL -> DisclosedButRemovedFromCRL
UPDATE ccadb_certificate_temp cct
	SET DISCLOSURE_STATUS = 'DisclosedButRemovedFromCRL'
	FROM certificate c, crl_revoked cr, crl
	WHERE cct.DISCLOSURE_STATUS = 'DisclosedButInCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID
		AND cr.CA_ID = crl.CA_ID
		AND crl.THIS_UPDATE > cr.LAST_SEEN_CHECK_DATE;


\echo Tidying Up

ANALYZE ccadb_certificate_temp;

GRANT SELECT ON ccadb_certificate_temp TO httpd;

DROP TABLE ccadb_certificate_import;

UPDATE ccadb_certificate_temp cct
	SET LAST_DISCLOSURE_STATUS_CHANGE = cc.LAST_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256
		AND cct.DISCLOSURE_STATUS = cc.DISCLOSURE_STATUS
		AND cc.LAST_DISCLOSURE_STATUS_CHANGE IS NOT NULL;

GRANT SELECT ON ccadb_certificate_temp TO guest;

DROP TABLE ccadb_certificate;

ALTER TABLE ccadb_certificate_temp RENAME TO ccadb_certificate;

ALTER INDEX cc_c_temp RENAME TO cc_c;

ALTER INDEX cc_ds_c_temp RENAME TO cc_ds_c;

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-disclosures,0}'::text[]), 1, 6);
