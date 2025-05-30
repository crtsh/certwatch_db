\timing on

\set ON_ERROR_STOP on

BEGIN WORK;

\echo Importing All CCADB Certificate Records

CREATE TEMPORARY TABLE ccadb_certificate_import (
	CA_OWNER					text,
	CCADB_RECORD_ID				text,
	CERT_NAME					text,
	PARENT_CCADB_RECORD_ID		text,
	PARENT_CERT_NAME			text,
	CERT_RECORD_TYPE			text,
	SUBORDINATE_CA_OWNER		text,
	APPLE_STATUS				text,
	CHROME_STATUS				text,
	MICROSOFT_STATUS			text,
	MOZILLA_STATUS				text,
	STATUS_OF_ROOT_CERT			text,
	REVOCATION_STATUS			text,
	CERT_SHA256					text,
	PARENT_CERT_SHA256			text,
	VALID_FROM					text,
	VALID_TO					text,
	AUTHORITY_KEY_IDENTIFIER	text,
	SUBJECT_KEY_IDENTIFIER		text,
	IS_TECHNICALLY_CONSTRAINED	text,
	DERIVED_TRUST_BITS			text,
	FULL_CRL_URL				text,
	JSON_ARRAY_OF_CRL_URLS		text,
	AUDITOR						text,
	AUDITS_SAME_AS_PARENT		text,
	STANDARD_AUDIT_URL			text,
	STANDARD_AUDIT_TYPE			text,
	STANDARD_AUDIT_DATE			text,
	STANDARD_AUDIT_START		text,
	STANDARD_AUDIT_END			text,
	NETSEC_AUDIT_URL			text,
	NETSEC_AUDIT_TYPE			text,
	NETSEC_AUDIT_DATE			text,
	NETSEC_AUDIT_START			text,
	NETSEC_AUDIT_END			text,
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
	CODE_AUDIT_URL				text,
	CODE_AUDIT_TYPE				text,
	CODE_AUDIT_DATE				text,
	CODE_AUDIT_START			text,
	CODE_AUDIT_END				text,
	SMIME_AUDIT_URL				text,
	SMIME_AUDIT_TYPE			text,
	SMIME_AUDIT_DATE			text,
	SMIME_AUDIT_START			text,
	SMIME_AUDIT_END				text,
	VMC_AUDIT_URL				text,
	VMC_AUDIT_TYPE				text,
	VMC_AUDIT_DATE				text,
	VMC_AUDIT_START				text,
	VMC_AUDIT_END				text,
	POLICY_DOCUMENTATION		text,
	CA_DOCUMENT_REPOSITORY		text,
	CP_SAME_AS_PARENT			text,
	CP_URL						text,
	CP_LAST_UPDATED				text,
	CPS_SAME_AS_PARENT			text,
	CPS_URL						text,
	CPS_LAST_UPDATED			text,
	CP_CPS_SAME_AS_PARENT		text,
	CP_CPS_URL					text,
	CP_CPS_LAST_UPDATED			text,
	TEST_WEBSITE_VALID			text,
	TEST_WEBSITE_EXPIRED		text,
	TEST_WEBSITE_REVOKED		text,
	TLS_CAPABLE					text,
	TLSEV_CAPABLE				text,
	CODESIGNING_CAPABLE			text,
	SMIME_CAPABLE				text,
	COUNTRY						text,
	TRUST_BITS_FOR_ROOT_CERT	text,
	EV_OIDS_FOR_ROOT_CERT		text
) ON COMMIT DROP;

\COPY ccadb_certificate_import FROM 'ccadb_all_certificate_records.csv' CSV HEADER;

DELETE FROM ccadb_certificate_import
	WHERE LENGTH(CERT_SHA256) != 64;

CREATE TEMPORARY TABLE ccadb_certificate_temp (LIKE ccadb_certificate INCLUDING INDEXES);

INSERT INTO ccadb_certificate_temp (
		CERTIFICATE_ID,
		PARENT_CERTIFICATE_ID,
		PARENT_CCADB_RECORD_ID,
		PARENT_CERT_SHA256,
		VALID_FROM,
		VALID_TO,
		INCLUDED_CERTIFICATE_ID,
		INCLUDED_CERTIFICATE_OWNER,
		CCADB_RECORD_ID,
		CA_OWNER,
		SUBORDINATE_CA_OWNER,
		CERT_NAME,
		PARENT_CERT_NAME,
		CERT_RECORD_TYPE,
		REVOCATION_STATUS,
		CERT_SHA256,
		AUDITS_SAME_AS_PARENT,
		AUDITOR,
		STANDARD_AUDIT_URL,
		STANDARD_AUDIT_TYPE,
		STANDARD_AUDIT_DATE,
		STANDARD_AUDIT_START,
		STANDARD_AUDIT_END,
		NETSEC_AUDIT_URL,
		NETSEC_AUDIT_TYPE,
		NETSEC_AUDIT_DATE,
		NETSEC_AUDIT_START,
		NETSEC_AUDIT_END,
		BRSSL_AUDIT_URL,
		BRSSL_AUDIT_TYPE,
		BRSSL_AUDIT_DATE,
		BRSSL_AUDIT_START,
		BRSSL_AUDIT_END,
		EVSSL_AUDIT_URL,
		EVSSL_AUDIT_TYPE,
		EVSSL_AUDIT_DATE,
		EVSSL_AUDIT_START,
		EVSSL_AUDIT_END,
		CODE_AUDIT_URL,
		CODE_AUDIT_TYPE,
		CODE_AUDIT_DATE,
		CODE_AUDIT_START,
		CODE_AUDIT_END,
		SMIME_AUDIT_URL,
		SMIME_AUDIT_TYPE,
		SMIME_AUDIT_DATE,
		SMIME_AUDIT_START,
		SMIME_AUDIT_END,
		CP_SAME_AS_PARENT,
		CP_URL,
		CP_LAST_UPDATED,
		CPS_SAME_AS_PARENT,
		CPS_URL,
		CPS_LAST_UPDATED,
		CP_CPS_SAME_AS_PARENT,
		CP_CPS_URL,
		CP_CPS_LAST_UPDATED,
		TEST_WEBSITE_VALID,
		TEST_WEBSITE_EXPIRED,
		TEST_WEBSITE_REVOKED,
		IS_TECHNICALLY_CONSTRAINED,
		APPLE_STATUS,
		MOZILLA_STATUS,
		MICROSOFT_STATUS,
		CHROME_STATUS,
		DERIVED_TRUST_BITS,
		STATUS_OF_ROOT_CERT,
		ISSUER_CN,
		ISSUER_O,
		SUBJECT_CN,
		SUBJECT_O,
		MOZILLA_DISCLOSURE_STATUS,
		MICROSOFT_DISCLOSURE_STATUS,
		APPLE_DISCLOSURE_STATUS,
		CHROME_DISCLOSURE_STATUS,
		LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE,
		LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE,
		LAST_APPLE_DISCLOSURE_STATUS_CHANGE,
		LAST_CHROME_DISCLOSURE_STATUS_CHANGE,
		FULL_CRL_URL,
		JSON_ARRAY_OF_CRL_URLS,
		TRUST_BITS_FOR_ROOT_CERT,
		EV_OIDS_FOR_ROOT_CERT
	)
	SELECT	c.ID					CERTIFICATE_ID,
			NULL					PARENT_CERTIFICATE_ID,
			PARENT_CCADB_RECORD_ID,
			PARENT_CERT_SHA256,
			VALID_FROM,
			VALID_TO,
			NULL					INCLUDED_CERTIFICATE_ID,
			NULL					INCLUDED_CERTIFICATE_OWNER,
			cci.CCADB_RECORD_ID,
			cci.CA_OWNER,
			cci.SUBORDINATE_CA_OWNER,
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
			CASE WHEN (cci.NETSEC_AUDIT_URL = '') THEN NULL
				ELSE cci.NETSEC_AUDIT_URL
			END NETSEC_AUDIT_URL,
			CASE WHEN (cci.NETSEC_AUDIT_TYPE = '') THEN NULL
				ELSE cci.NETSEC_AUDIT_TYPE
			END NETSEC_AUDIT_TYPE,
			CASE WHEN (cci.NETSEC_AUDIT_DATE = '') THEN NULL
				ELSE to_date(cci.NETSEC_AUDIT_DATE, 'YYYY.MM.DD')
			END NETSEC_AUDIT_DATE,
			CASE WHEN (cci.NETSEC_AUDIT_START = '') THEN NULL
				ELSE to_date(cci.NETSEC_AUDIT_START, 'YYYY.MM.DD')
			END NETSEC_AUDIT_START,
			CASE WHEN (cci.NETSEC_AUDIT_END = '') THEN NULL
				ELSE to_date(cci.NETSEC_AUDIT_END, 'YYYY.MM.DD')
			END NETSEC_AUDIT_END,
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
			CASE WHEN (cci.CODE_AUDIT_URL = '') THEN NULL
				ELSE cci.CODE_AUDIT_URL
			END CODE_AUDIT_URL,
			CASE WHEN (cci.CODE_AUDIT_TYPE = '') THEN NULL
				ELSE cci.CODE_AUDIT_TYPE
			END CODE_AUDIT_TYPE,
			CASE WHEN (cci.CODE_AUDIT_DATE = '') THEN NULL
				ELSE to_date(cci.CODE_AUDIT_DATE, 'YYYY.MM.DD')
			END CODE_AUDIT_DATE,
			CASE WHEN (cci.CODE_AUDIT_START = '') THEN NULL
				ELSE to_date(cci.CODE_AUDIT_START, 'YYYY.MM.DD')
			END CODE_AUDIT_START,
			CASE WHEN (cci.CODE_AUDIT_END = '') THEN NULL
				ELSE to_date(cci.CODE_AUDIT_END, 'YYYY.MM.DD')
			END CODE_AUDIT_END,
			CASE WHEN (cci.SMIME_AUDIT_URL = '') THEN NULL
				ELSE cci.SMIME_AUDIT_URL
			END SMIME_AUDIT_URL,
			CASE WHEN (cci.SMIME_AUDIT_TYPE = '') THEN NULL
				ELSE cci.SMIME_AUDIT_TYPE
			END SMIME_AUDIT_TYPE,
			CASE WHEN (cci.SMIME_AUDIT_DATE = '') THEN NULL
				ELSE to_date(cci.SMIME_AUDIT_DATE, 'YYYY.MM.DD')
			END SMIME_AUDIT_DATE,
			CASE WHEN (cci.SMIME_AUDIT_START = '') THEN NULL
				ELSE to_date(cci.SMIME_AUDIT_START, 'YYYY.MM.DD')
			END SMIME_AUDIT_START,
			CASE WHEN (cci.SMIME_AUDIT_END = '') THEN NULL
				ELSE to_date(cci.SMIME_AUDIT_END, 'YYYY.MM.DD')
			END SMIME_AUDIT_END,
			CASE WHEN (cci.CP_SAME_AS_PARENT = '') THEN FALSE
				ELSE (lower(cci.CP_SAME_AS_PARENT) = 'true')
			END CP_SAME_AS_PARENT,
			CASE WHEN (cci.CP_URL = '') THEN NULL
				ELSE cci.CP_URL
			END CP_URL,
			CASE WHEN (cci.CP_LAST_UPDATED = '') THEN NULL
				ELSE to_date(cci.CP_LAST_UPDATED, 'YYYY.MM.DD')
			END CP_LAST_UPDATED,
			CASE WHEN (cci.CPS_SAME_AS_PARENT = '') THEN FALSE
				ELSE (lower(cci.CPS_SAME_AS_PARENT) = 'true')
			END CPS_SAME_AS_PARENT,
			CASE WHEN (cci.CPS_URL = '') THEN NULL
				ELSE cci.CPS_URL
			END CPS_URL,
			CASE WHEN (cci.CPS_LAST_UPDATED = '') THEN NULL
				ELSE to_date(cci.CPS_LAST_UPDATED, 'YYYY.MM.DD')
			END CPS_LAST_UPDATED,
			CASE WHEN (cci.CP_CPS_SAME_AS_PARENT = '') THEN FALSE
				ELSE (lower(cci.CP_CPS_SAME_AS_PARENT) = 'true')
			END CP_CPS_SAME_AS_PARENT,
			CASE WHEN (cci.CP_CPS_URL = '') THEN NULL
				ELSE cci.CP_CPS_URL
			END CP_CPS_URL,
			CASE WHEN (cci.CP_CPS_LAST_UPDATED = '') THEN NULL
				ELSE to_date(cci.CP_CPS_LAST_UPDATED, 'YYYY.MM.DD')
			END CP_CPS_LAST_UPDATED,
			cci.TEST_WEBSITE_VALID,
			cci.TEST_WEBSITE_EXPIRED,
			cci.TEST_WEBSITE_REVOKED,
			cci.IS_TECHNICALLY_CONSTRAINED,
			cci.APPLE_STATUS,
			cci.MOZILLA_STATUS,
			cci.MICROSOFT_STATUS,
			cci.CHROME_STATUS,
			cci.DERIVED_TRUST_BITS,
			cci.STATUS_OF_ROOT_CERT,
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', FALSE) LIMIT 1)		ISSUER_CN,
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', FALSE) LIMIT 1)	ISSUER_O,
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) LIMIT 1)			SUBJECT_CN,
			(SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) LIMIT 1)	SUBJECT_O,
			CASE cci.REVOCATION_STATUS
				WHEN 'Revoked' THEN 'Revoked'::disclosure_status_type
				WHEN 'Parent Cert Revoked' THEN 'ParentRevoked'::disclosure_status_type
				ELSE 'Disclosed'::disclosure_status_type
			END MOZILLA_DISCLOSURE_STATUS,
			CASE cci.REVOCATION_STATUS
				WHEN 'Revoked' THEN 'Revoked'::disclosure_status_type
				WHEN 'Parent Cert Revoked' THEN 'ParentRevoked'::disclosure_status_type
				ELSE 'Disclosed'::disclosure_status_type
			END MICROSOFT_DISCLOSURE_STATUS,
			CASE cci.REVOCATION_STATUS
				WHEN 'Revoked' THEN 'Revoked'::disclosure_status_type
				WHEN 'Parent Cert Revoked' THEN 'ParentRevoked'::disclosure_status_type
				ELSE 'Disclosed'::disclosure_status_type
			END APPLE_DISCLOSURE_STATUS,
			CASE cci.REVOCATION_STATUS
				WHEN 'Revoked' THEN 'Revoked'::disclosure_status_type
				WHEN 'Parent Cert Revoked' THEN 'ParentRevoked'::disclosure_status_type
				ELSE 'Disclosed'::disclosure_status_type
			END CHROME_DISCLOSURE_STATUS,
			now() AT TIME ZONE 'UTC'	LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE,
			now() AT TIME ZONE 'UTC'	LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE,
			now() AT TIME ZONE 'UTC'	LAST_APPLE_DISCLOSURE_STATUS_CHANGE,
			now() AT TIME ZONE 'UTC'	LAST_CHROME_DISCLOSURE_STATUS_CHANGE,
			cci.FULL_CRL_URL,
			cci.JSON_ARRAY_OF_CRL_URLS,
			cci.TRUST_BITS_FOR_ROOT_CERT,
			cci.EV_OIDS_FOR_ROOT_CERT
		FROM ccadb_certificate_import cci
			LEFT OUTER JOIN certificate c ON (decode(replace(cci.CERT_SHA256, ':', ''), 'hex') = digest(c.CERTIFICATE, 'sha256'))
		WHERE cci.CA_OWNER != 'Example CA';


\echo Finding All CA Certificates
INSERT INTO ccadb_certificate_temp (
		CERTIFICATE_ID, CERT_NAME,
		ISSUER_O,
		ISSUER_CN,
		SUBJECT_O,
		SUBJECT_CN,
		CERT_SHA256,
		MOZILLA_DISCLOSURE_STATUS, LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE,
		MICROSOFT_DISCLOSURE_STATUS, LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE,
		APPLE_DISCLOSURE_STATUS, LAST_APPLE_DISCLOSURE_STATUS_CHANGE,
		CHROME_DISCLOSURE_STATUS, LAST_CHROME_DISCLOSURE_STATUS_CHANGE
	)
	SELECT c.ID, get_ca_name_attribute(cac.CA_ID),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName'),
			get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName'),
			get_ca_name_attribute(cac.CA_ID, 'organizationName'),
			get_ca_name_attribute(cac.CA_ID, 'commonName'),
			digest(c.CERTIFICATE, 'sha256'),
			'Undisclosed', now() AT TIME ZONE 'UTC',
			'Undisclosed', now() AT TIME ZONE 'UTC',
			'Undisclosed', now() AT TIME ZONE 'UTC',
			'Undisclosed', now() AT TIME ZONE 'UTC'
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

/* Look for the parent.  Treat a Root Certificate in the CCADB as its own parent... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = CERTIFICATE_ID
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CERT_RECORD_TYPE = 'Root Certificate';
/* ...then prioritize the "parent" records indicated by the CCADB... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = c_parent.ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND digest(c_parent.CERTIFICATE, 'sha256') = decode(replace(cct.PARENT_CERT_SHA256, ':', ''), 'hex');
/* ...then Disclosed Root CA certs that are unexpired... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent, ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND coalesce(x509_notAfter(c_parent.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
		AND c_parent.ID = cct_parent.CERTIFICATE_ID
		AND cct_parent.CERT_RECORD_TYPE = 'Root Certificate';
/* ...then Disclosed Intermediate CA certs that are unexpired... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID
	FROM certificate c, ca_certificate cac_parent, certificate c_parent, ccadb_certificate_temp cct_parent
	WHERE cct.CERTIFICATE_ID IS NOT NULL
		AND cct.PARENT_CERTIFICATE_ID IS NULL
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac_parent.CA_ID
		AND cac_parent.CERTIFICATE_ID = c_parent.ID
		AND coalesce(x509_notAfter(c_parent.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
		AND c_parent.ID = cct_parent.CERTIFICATE_ID
		AND cct_parent.CERT_RECORD_TYPE IS NOT NULL;
/* ...then any other CA certs trusted by Microsoft, Mozilla, Apple, or Chrome... */
UPDATE ccadb_certificate_temp cct
	SET PARENT_CERTIFICATE_ID = (
		SELECT c_parent.ID
			FROM certificate c, ca_certificate cac_parent, certificate c_parent, ca_trust_purpose ctp
			WHERE cct.CERTIFICATE_ID = c.ID
				AND c.ISSUER_CA_ID = cac_parent.CA_ID
				AND cac_parent.CERTIFICATE_ID = c_parent.ID
				AND c.ID != c_parent.ID
				AND c_parent.ISSUER_CA_ID = ctp.CA_ID
				AND ctp.TRUST_CONTEXT_ID IN (1, 5, 12, 6)
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


/* Handle Subordinate CA Owner inheritance.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling Subordinate CA Owner inheritance
DO $$
BEGIN
	FOR i IN 1..4 LOOP
		UPDATE ccadb_certificate_temp cct
			SET SUBORDINATE_CA_OWNER = coalesce(nullif(cct.SUBORDINATE_CA_OWNER, ''), cct_parent.SUBORDINATE_CA_OWNER)
			FROM ccadb_certificate_temp cct_parent
			WHERE cct.CERTIFICATE_ID IS NOT NULL
				AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
	END LOOP;
END $$;


/* Handle CP, CPS, and CP/CPS inheritance.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling CP, CPS, and CP/CPS Inheritance
DO $$
BEGIN
	FOR i IN 1..4 LOOP
		UPDATE ccadb_certificate_temp cct
			SET CP_URL = coalesce(cct.CP_URL, cct_parent.CP_URL),
				CP_LAST_UPDATED = coalesce(cct.CP_LAST_UPDATED, cct_parent.CP_LAST_UPDATED)
			FROM ccadb_certificate_temp cct_parent
			WHERE cct.CERTIFICATE_ID IS NOT NULL
				AND cct.CP_SAME_AS_PARENT
				AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
		UPDATE ccadb_certificate_temp cct
			SET CPS_URL = coalesce(cct.CPS_URL, cct_parent.CPS_URL),
				CPS_LAST_UPDATED = coalesce(cct.CPS_LAST_UPDATED, cct_parent.CPS_LAST_UPDATED)
			FROM ccadb_certificate_temp cct_parent
			WHERE cct.CERTIFICATE_ID IS NOT NULL
				AND cct.CPS_SAME_AS_PARENT
				AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
		UPDATE ccadb_certificate_temp cct
			SET CP_CPS_URL = coalesce(cct.CP_CPS_URL, cct_parent.CP_CPS_URL),
				CP_CPS_LAST_UPDATED = coalesce(cct.CP_CPS_LAST_UPDATED, cct_parent.CP_CPS_LAST_UPDATED)
			FROM ccadb_certificate_temp cct_parent
			WHERE cct.CERTIFICATE_ID IS NOT NULL
				AND cct.CP_CPS_SAME_AS_PARENT
				AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
	END LOOP;
END $$;

/* Handle inheritance of audit details.  Repeat several times, to populate several levels of Sub-CA */
\echo Handling Audit Inheritance
DO $$
BEGIN
	FOR i IN 1..4 LOOP
		UPDATE ccadb_certificate_temp cct
			SET STANDARD_AUDIT_URL = coalesce(cct.STANDARD_AUDIT_URL, cct_parent.STANDARD_AUDIT_URL),
				STANDARD_AUDIT_TYPE = coalesce(cct.STANDARD_AUDIT_TYPE, cct_parent.STANDARD_AUDIT_TYPE),
				STANDARD_AUDIT_DATE = coalesce(cct.STANDARD_AUDIT_DATE, cct_parent.STANDARD_AUDIT_DATE),
				STANDARD_AUDIT_START = coalesce(cct.STANDARD_AUDIT_START, cct_parent.STANDARD_AUDIT_START),
				STANDARD_AUDIT_END = coalesce(cct.STANDARD_AUDIT_END, cct_parent.STANDARD_AUDIT_END),
				NETSEC_AUDIT_URL = coalesce(cct.NETSEC_AUDIT_URL, cct_parent.NETSEC_AUDIT_URL),
				NETSEC_AUDIT_TYPE = coalesce(cct.NETSEC_AUDIT_TYPE, cct_parent.NETSEC_AUDIT_TYPE),
				NETSEC_AUDIT_DATE = coalesce(cct.NETSEC_AUDIT_DATE, cct_parent.NETSEC_AUDIT_DATE),
				NETSEC_AUDIT_START = coalesce(cct.NETSEC_AUDIT_START, cct_parent.NETSEC_AUDIT_START),
				NETSEC_AUDIT_END = coalesce(cct.NETSEC_AUDIT_END, cct_parent.NETSEC_AUDIT_END),
				BRSSL_AUDIT_URL = coalesce(cct.BRSSL_AUDIT_URL, cct_parent.BRSSL_AUDIT_URL),
				BRSSL_AUDIT_TYPE = coalesce(cct.BRSSL_AUDIT_TYPE, cct_parent.BRSSL_AUDIT_TYPE),
				BRSSL_AUDIT_DATE = coalesce(cct.BRSSL_AUDIT_DATE, cct_parent.BRSSL_AUDIT_DATE),
				BRSSL_AUDIT_START = coalesce(cct.BRSSL_AUDIT_START, cct_parent.BRSSL_AUDIT_START),
				BRSSL_AUDIT_END = coalesce(cct.BRSSL_AUDIT_END, cct_parent.BRSSL_AUDIT_END),
				EVSSL_AUDIT_URL = coalesce(cct.EVSSL_AUDIT_URL, cct_parent.EVSSL_AUDIT_URL),
				EVSSL_AUDIT_TYPE = coalesce(cct.EVSSL_AUDIT_TYPE, cct_parent.EVSSL_AUDIT_TYPE),
				EVSSL_AUDIT_DATE = coalesce(cct.EVSSL_AUDIT_DATE, cct_parent.EVSSL_AUDIT_DATE),
				EVSSL_AUDIT_START = coalesce(cct.EVSSL_AUDIT_START, cct_parent.EVSSL_AUDIT_START),
				EVSSL_AUDIT_END = coalesce(cct.EVSSL_AUDIT_END, cct_parent.EVSSL_AUDIT_END),
				CODE_AUDIT_URL = coalesce(cct.CODE_AUDIT_URL, cct_parent.CODE_AUDIT_URL),
				CODE_AUDIT_TYPE = coalesce(cct.CODE_AUDIT_TYPE, cct_parent.CODE_AUDIT_TYPE),
				CODE_AUDIT_DATE = coalesce(cct.CODE_AUDIT_DATE, cct_parent.CODE_AUDIT_DATE),
				CODE_AUDIT_START = coalesce(cct.CODE_AUDIT_START, cct_parent.CODE_AUDIT_START),
				CODE_AUDIT_END = coalesce(cct.CODE_AUDIT_END, cct_parent.CODE_AUDIT_END),
				SMIME_AUDIT_URL = coalesce(cct.SMIME_AUDIT_URL, cct_parent.SMIME_AUDIT_URL),
				SMIME_AUDIT_TYPE = coalesce(cct.SMIME_AUDIT_TYPE, cct_parent.SMIME_AUDIT_TYPE),
				SMIME_AUDIT_DATE = coalesce(cct.SMIME_AUDIT_DATE, cct_parent.SMIME_AUDIT_DATE),
				SMIME_AUDIT_START = coalesce(cct.SMIME_AUDIT_START, cct_parent.SMIME_AUDIT_START),
				SMIME_AUDIT_END = coalesce(cct.SMIME_AUDIT_END, cct_parent.SMIME_AUDIT_END),
				AUDITOR = coalesce(cct.AUDITOR, cct_parent.AUDITOR)
			FROM ccadb_certificate_temp cct_parent
			WHERE cct.CERTIFICATE_ID IS NOT NULL
				AND cct.AUDITS_SAME_AS_PARENT
				AND cct.PARENT_CERTIFICATE_ID = cct_parent.CERTIFICATE_ID;
	END LOOP;
END $$;


\echo Handle the Expired cases
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = CASE MOZILLA_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'Expired'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButExpired'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedButExpired'::disclosure_status_type
			ELSE MOZILLA_DISCLOSURE_STATUS
		END,
		MICROSOFT_DISCLOSURE_STATUS = CASE MICROSOFT_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'Expired'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButExpired'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedButExpired'::disclosure_status_type
			ELSE MICROSOFT_DISCLOSURE_STATUS
		END,
		APPLE_DISCLOSURE_STATUS = CASE APPLE_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'Expired'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButExpired'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedButExpired'::disclosure_status_type
			ELSE APPLE_DISCLOSURE_STATUS
		END,
		CHROME_DISCLOSURE_STATUS = CASE CHROME_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'Expired'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButExpired'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedButExpired'::disclosure_status_type
			ELSE CHROME_DISCLOSURE_STATUS
		END
	FROM certificate c
	WHERE cct.CERTIFICATE_ID = c.ID
		AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) < now();


\echo Undisclosed -> NoKnownSuitableTrustPath
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'NoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Undisclosed'
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
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'NoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'NoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.IS_TIME_VALID
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'NoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND ctp.IS_TIME_VALID
		);

\echo Undisclosed -> AllSuitablePathsRevoked
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Undisclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);

\echo Handle the OneCRL and disallowedcert.stl cases
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = CASE MOZILLA_DISCLOSURE_STATUS
			WHEN 'Revoked' THEN 'RevokedViaOneCRL'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButInOneCRL'::disclosure_status_type
			WHEN 'RevokedButExpired' THEN 'RevokedViaOneCRLButExpired'::disclosure_status_type
		END
	FROM mozilla_onecrl m
	WHERE cct.MOZILLA_DISCLOSURE_STATUS IN ('Revoked', 'Disclosed', 'RevokedButExpired')
		AND cct.CERTIFICATE_ID = m.CERTIFICATE_ID;
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'RevokedAndShouldBeAddedToOneCRL'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Revoked'
		AND cct.CERTIFICATE_ID = c.ID
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
		)
		AND (
			x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
			OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
			OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')
		);
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'RevokedViaOneCRLButNotNeeded'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'RevokedViaOneCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT (
			EXISTS (
				SELECT 1
					FROM ca_trust_purpose ctp
					WHERE ctp.CA_ID = c.ISSUER_CA_ID
						AND ctp.TRUST_CONTEXT_ID = 5
						AND ctp.TRUST_PURPOSE_ID = 1
			)
			AND (
				x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
				OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
				OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')
			)
		);

UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = CASE MICROSOFT_DISCLOSURE_STATUS
			WHEN 'Revoked' THEN 'RevokedViaOneCRL'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButInOneCRL'::disclosure_status_type
		END
	FROM microsoft_disallowedcert md
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS IN ('Revoked', 'Disclosed')
		AND cct.CERTIFICATE_ID = md.CERTIFICATE_ID;

\echo Handle the Technically Constrained cases
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = CASE MOZILLA_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'TechnicallyConstrainedOther'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButConstrained'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedAndTechnicallyConstrained'::disclosure_status_type
			WHEN 'RevokedViaOneCRL' THEN 'RevokedViaOneCRLButTechnicallyConstrained'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS IN ('Undisclosed', 'Disclosed', 'Revoked', 'RevokedViaOneCRL')
		AND coalesce(cct.CERT_RECORD_TYPE, 'Undisclosed') != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = CASE MICROSOFT_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'TechnicallyConstrainedOther'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButConstrained'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS IN ('Undisclosed', 'Disclosed')
		AND coalesce(cct.CERT_RECORD_TYPE, 'Undisclosed') != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = CASE APPLE_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'TechnicallyConstrained'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButConstrained'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedAndTechnicallyConstrained'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS IN ('Undisclosed', 'Disclosed', 'Revoked')
		AND coalesce(cct.CERT_RECORD_TYPE, 'Undisclosed') != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = CASE CHROME_DISCLOSURE_STATUS
			WHEN 'Undisclosed' THEN 'TechnicallyConstrainedOther'::disclosure_status_type
			WHEN 'Disclosed' THEN 'DisclosedButConstrained'::disclosure_status_type
			WHEN 'Revoked' THEN 'RevokedAndTechnicallyConstrained'::disclosure_status_type
		END
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS IN ('Undisclosed', 'Disclosed', 'Revoked')
		AND coalesce(cct.CERT_RECORD_TYPE, 'Undisclosed') != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND is_technically_constrained(c.CERTIFICATE);

UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
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
	SET MICROSOFT_DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
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
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID = 1
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
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
					AND ctp.TRUST_CONTEXT_ID = 6
					AND ctp.TRUST_PURPOSE_ID = 1
		);

UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 3
		);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'TechnicallyConstrained'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'TechnicallyConstrainedOther'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID = 3
		);

\echo Disclosed -> DisclosedButNoKnownSuitableTrustPath
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedButNoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS IN ('Disclosed', 'Revoked', 'ParentRevoked')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND ctp.IS_TIME_VALID
		);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedButNoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS IN ('Disclosed', 'Revoked', 'ParentRevoked')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND ctp.IS_TIME_VALID
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedButNoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS IN ('Disclosed', 'Revoked', 'ParentRevoked')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.IS_TIME_VALID
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedButNoKnownSuitableTrustPath'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS IN ('Disclosed', 'Revoked', 'ParentRevoked')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND ctp.IS_TIME_VALID
		);

\echo ParentRevoked -> ParentRevokedButNotAllParents
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'ParentRevokedButNotAllParents'
	FROM certificate c, ca_certificate cac, ccadb_certificate cc2
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'ParentRevoked'
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac.CA_ID
		AND cac.CERTIFICATE_ID = cc2.CERTIFICATE_ID
		AND cc2.MOZILLA_DISCLOSURE_STATUS NOT IN (
			'AllSuitablePathsRevoked',
			'NoKnownSuitableTrustPath',
			'TechnicallyConstrainedOther',
			'Expired',
			'Revoked',
			'RevokedAndTechnicallyConstrained',
			'ParentRevoked',
			'ParentRevokedButInOneCRL',
			'RevokedButExpired',
			'RevokedAndShouldBeAddedToOneCRL',
			'RevokedViaOneCRL',
			'RevokedViaOneCRLButExpired',
			'RevokedViaOneCRLButTechnicallyConstrained',
			'RevokedViaOneCRLButNotNeeded',
			'DisclosedButExpired',
			'DisclosedButNoKnownSuitableTrustPath',
			'DisclosedButInOneCRL'
		)
		AND NOT (
			coalesce(cc2.CERT_RECORD_TYPE, '') = 'Root Certificate'
			AND NOT EXISTS (
				SELECT 1
					FROM root_trust_purpose rtp
					WHERE cc2.CERTIFICATE_ID = rtp.CERTIFICATE_ID
						AND rtp.TRUST_CONTEXT_ID = 5
			)
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'ParentRevokedButNotAllParents'
	FROM certificate c, ca_certificate cac, ccadb_certificate cc2
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'ParentRevoked'
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac.CA_ID
		AND cac.CERTIFICATE_ID = cc2.CERTIFICATE_ID
		AND cc2.APPLE_DISCLOSURE_STATUS NOT IN (
			'AllSuitablePathsRevoked',
			'NoKnownSuitableTrustPath',
			'TechnicallyConstrainedOther',
			'Expired',
			'Revoked',
			'RevokedAndTechnicallyConstrained',
			'ParentRevoked',
			'RevokedButExpired',
			'DisclosedButExpired',
			'DisclosedButNoKnownSuitableTrustPath'
		)
		AND NOT (
			coalesce(cc2.CERT_RECORD_TYPE, '') = 'Root Certificate'
			AND NOT EXISTS (
				SELECT 1
					FROM root_trust_purpose rtp
					WHERE cc2.CERTIFICATE_ID = rtp.CERTIFICATE_ID
						AND rtp.TRUST_CONTEXT_ID = 12
			)
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'ParentRevokedButNotAllParents'
	FROM certificate c, ca_certificate cac, ccadb_certificate cc2
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'ParentRevoked'
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ISSUER_CA_ID = cac.CA_ID
		AND cac.CERTIFICATE_ID = cc2.CERTIFICATE_ID
		AND cc2.CHROME_DISCLOSURE_STATUS NOT IN (
			'AllSuitablePathsRevoked',
			'NoKnownSuitableTrustPath',
			'TechnicallyConstrainedOther',
			'Expired',
			'Revoked',
			'RevokedAndTechnicallyConstrained',
			'ParentRevoked',
			'RevokedButExpired',
			'DisclosedButExpired',
			'DisclosedButNoKnownSuitableTrustPath'
		)
		AND NOT (
			coalesce(cc2.CERT_RECORD_TYPE, '') = 'Root Certificate'
			AND NOT EXISTS (
				SELECT 1
					FROM root_trust_purpose rtp
					WHERE cc2.CERTIFICATE_ID = rtp.CERTIFICATE_ID
						AND rtp.TRUST_CONTEXT_ID = 6
			)
		);

\echo ParentRevoked -> ParentRevokedButInOneCRL
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'ParentRevokedButInOneCRL'
	FROM mozilla_onecrl m
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'ParentRevoked'
		AND cct.CERTIFICATE_ID = m.CERTIFICATE_ID;

\echo Disclosed -> DisclosureIncomplete
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (
			(
				(coalesce(cct.CP_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(cct.CPS_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(coalesce(cct.CP_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (coalesce(coalesce(cct.CPS_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (cct.STANDARD_AUDIT_URL IS NULL)
				OR (cct.STANDARD_AUDIT_TYPE IS NULL)
				OR (cct.STANDARD_AUDIT_DATE IS NULL)
				OR (cct.STANDARD_AUDIT_START IS NULL)
				OR (cct.STANDARD_AUDIT_END IS NULL)
				-- TODO: Standalone NetSec audits will be required by MRSP 3.0. Uncomment these lines once every CA should have one.
/*				OR (cct.NETSEC_AUDIT_URL IS NULL)
				OR (cct.NETSEC_AUDIT_TYPE IS NULL)
				OR (cct.NETSEC_AUDIT_DATE IS NULL)
				OR (cct.NETSEC_AUDIT_START IS NULL)
				OR (cct.NETSEC_AUDIT_END IS NULL)*/
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 5
							AND ctp.TRUST_PURPOSE_ID = 1
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_ONECRL)
				)
				AND (
					(cct.BRSSL_AUDIT_URL IS NULL)
					OR (cct.BRSSL_AUDIT_TYPE IS NULL)
					OR (cct.BRSSL_AUDIT_DATE IS NULL)
					OR (cct.BRSSL_AUDIT_START IS NULL)
					OR (cct.BRSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp, trust_purpose tp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 5
							AND ctp.TRUST_PURPOSE_ID >= 100
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND x509_isPolicyPermitted(c.CERTIFICATE, tp.PURPOSE_OID)
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_ONECRL)
				)
				AND (
					(cct.EVSSL_AUDIT_URL IS NULL)
					OR (cct.EVSSL_AUDIT_TYPE IS NULL)
					OR (cct.EVSSL_AUDIT_DATE IS NULL)
					OR (cct.EVSSL_AUDIT_START IS NULL)
					OR (cct.EVSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 5
							AND ctp.TRUST_PURPOSE_ID = 3
							AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
							AND ctp.IS_TIME_VALID
				)
				AND (
					(cct.SMIME_AUDIT_URL IS NULL)
					OR (cct.SMIME_AUDIT_TYPE IS NULL)
					OR (cct.SMIME_AUDIT_DATE IS NULL)
					OR (cct.SMIME_AUDIT_START IS NULL)
					OR (cct.SMIME_AUDIT_END IS NULL)
				)
			)
		);
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = CASE coalesce(ca.NUM_ISSUED[1], 0) + coalesce(ca.NUM_ISSUED[2], 0)
			WHEN 0 THEN 'CRLDisclosureIncompleteForPossiblyDormantCA'::disclosure_status_type
			ELSE 'DisclosureIncomplete'::disclosure_status_type
		END
	FROM ca_certificate cac, ca
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE IN ('Root Certificate', 'Intermediate Certificate')
		AND nullif(cct.FULL_CRL_URL, '') IS NULL
		AND nullif(nullif(cct.JSON_ARRAY_OF_CRL_URLS, ''), '[""]') IS NULL
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND cac.CA_ID = ca.ID
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = ca.ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c, ca_certificate cac
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE IN ('Root Certificate', 'Intermediate Certificate')
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ID = cac.CERTIFICATE_ID
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE cac.CA_ID = ctp.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		)
		AND (
			(
				cct.FULL_CRL_URL = 'revoked'
				AND cct.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
			)
			OR (
				cct.FULL_CRL_URL = 'expired'
				AND x509_notAfter(c.CERTIFICATE) > now() AT TIME ZONE 'UTC'
			)
			OR EXISTS (
				SELECT 1
					FROM crl
					WHERE cac.CA_ID = crl.CA_ID
						AND cct.FULL_CRL_URL = crl.DISTRIBUTION_POINT_URL
						AND (
							(crl.ERROR_MESSAGE IS NOT NULL)
							OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
						)
			)
			OR EXISTS (
				SELECT 1
					FROM crl, json_array_elements_text(cct.JSON_ARRAY_OF_CRL_URLS::json) json_crl_url
					WHERE cac.CA_ID = crl.CA_ID
						AND length(cct.JSON_ARRAY_OF_CRL_URLS) > 4	-- Longer than [""].
						AND crl.DISTRIBUTION_POINT_URL = json_crl_url
						AND (
							(crl.ERROR_MESSAGE IS NOT NULL)
							OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
						)
			)
		);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (
			(
				(coalesce(cct.CP_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(cct.CPS_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(coalesce(cct.CP_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (coalesce(coalesce(cct.CPS_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (cct.STANDARD_AUDIT_URL IS NULL)
				OR (cct.STANDARD_AUDIT_TYPE IS NULL)
				OR (cct.STANDARD_AUDIT_DATE IS NULL)
				OR (cct.STANDARD_AUDIT_START IS NULL)
				OR (cct.STANDARD_AUDIT_END IS NULL)
				-- TODO: Uncomment these lines once every CA should have a Standalone NetSec audit.
/*				OR (cct.NETSEC_AUDIT_URL IS NULL)
				OR (cct.NETSEC_AUDIT_TYPE IS NULL)
				OR (cct.NETSEC_AUDIT_DATE IS NULL)
				OR (cct.NETSEC_AUDIT_START IS NULL)
				OR (cct.NETSEC_AUDIT_END IS NULL)*/
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 1
							AND ctp.TRUST_PURPOSE_ID = 1
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL)
				)
				AND (
					(cct.BRSSL_AUDIT_URL IS NULL)
					OR (cct.BRSSL_AUDIT_TYPE IS NULL)
					OR (cct.BRSSL_AUDIT_DATE IS NULL)
					OR (cct.BRSSL_AUDIT_START IS NULL)
					OR (cct.BRSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp, trust_purpose tp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 1
							AND ctp.TRUST_PURPOSE_ID >= 100
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND x509_isPolicyPermitted(c.CERTIFICATE, tp.PURPOSE_OID)
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL)
				)
				AND (
					(cct.EVSSL_AUDIT_URL IS NULL)
					OR (cct.EVSSL_AUDIT_TYPE IS NULL)
					OR (cct.EVSSL_AUDIT_DATE IS NULL)
					OR (cct.EVSSL_AUDIT_START IS NULL)
					OR (cct.EVSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 1
							AND ctp.TRUST_PURPOSE_ID = 3
							AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL)
				)
				AND (
					(cct.SMIME_AUDIT_URL IS NULL)
					OR (cct.SMIME_AUDIT_TYPE IS NULL)
					OR (cct.SMIME_AUDIT_DATE IS NULL)
					OR (cct.SMIME_AUDIT_START IS NULL)
					OR (cct.SMIME_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 1
							AND ctp.TRUST_PURPOSE_ID = 4
							AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.3')
							AND ctp.IS_TIME_VALID
							AND (NOT ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL)
				)
				AND (
					(cct.CODE_AUDIT_URL IS NULL)
					OR (cct.CODE_AUDIT_TYPE IS NULL)
					OR (cct.CODE_AUDIT_DATE IS NULL)
					OR (cct.CODE_AUDIT_START IS NULL)
					OR (cct.CODE_AUDIT_END IS NULL)
				)
			)
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (
			(
				(coalesce(cct.CP_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(cct.CPS_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(coalesce(cct.CP_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (coalesce(coalesce(cct.CPS_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (cct.STANDARD_AUDIT_URL IS NULL)
				OR (cct.STANDARD_AUDIT_TYPE IS NULL)
				OR (cct.STANDARD_AUDIT_DATE IS NULL)
				OR (cct.STANDARD_AUDIT_START IS NULL)
				OR (cct.STANDARD_AUDIT_END IS NULL)
				-- TODO: Uncomment these lines once every CA should have a Standalone NetSec audit.
/*				OR (cct.NETSEC_AUDIT_URL IS NULL)
				OR (cct.NETSEC_AUDIT_TYPE IS NULL)
				OR (cct.NETSEC_AUDIT_DATE IS NULL)
				OR (cct.NETSEC_AUDIT_START IS NULL)
				OR (cct.NETSEC_AUDIT_END IS NULL)*/
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 12
							AND ctp.TRUST_PURPOSE_ID = 1
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
				)
				AND (
					(cct.BRSSL_AUDIT_URL IS NULL)
					OR (cct.BRSSL_AUDIT_TYPE IS NULL)
					OR (cct.BRSSL_AUDIT_DATE IS NULL)
					OR (cct.BRSSL_AUDIT_START IS NULL)
					OR (cct.BRSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp, trust_purpose tp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 12
							AND ctp.TRUST_PURPOSE_ID >= 100
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND x509_isPolicyPermitted(c.CERTIFICATE, tp.PURPOSE_OID)
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
				)
				AND (
					(cct.EVSSL_AUDIT_URL IS NULL)
					OR (cct.EVSSL_AUDIT_TYPE IS NULL)
					OR (cct.EVSSL_AUDIT_DATE IS NULL)
					OR (cct.EVSSL_AUDIT_START IS NULL)
					OR (cct.EVSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 12
							AND ctp.TRUST_PURPOSE_ID = 3
							AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
							AND ctp.IS_TIME_VALID
					)
				AND (
					(cct.SMIME_AUDIT_URL IS NULL)
					OR (cct.SMIME_AUDIT_TYPE IS NULL)
					OR (cct.SMIME_AUDIT_DATE IS NULL)
					OR (cct.SMIME_AUDIT_START IS NULL)
					OR (cct.SMIME_AUDIT_END IS NULL)
				)
			)
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = CASE coalesce(ca.NUM_ISSUED[1], 0) + coalesce(ca.NUM_ISSUED[2], 0)
			WHEN 0 THEN 'CRLDisclosureIncompleteForPossiblyDormantCA'::disclosure_status_type
			ELSE 'DisclosureIncomplete'::disclosure_status_type
		END
	FROM ca_certificate cac, ca
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE IN ('Root Certificate', 'Intermediate Certificate')
		AND nullif(cct.FULL_CRL_URL, '') IS NULL
		AND nullif(nullif(cct.JSON_ARRAY_OF_CRL_URLS, ''), '[""]') IS NULL
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND cac.CA_ID = ca.ID
		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = ca.ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.IS_TIME_VALID
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c, ca_certificate cac
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE IN ('Root Certificate', 'Intermediate Certificate')
		AND cct.CERTIFICATE_ID = c.ID
		AND c.ID = cac.CERTIFICATE_ID
		AND (
			(
				cct.FULL_CRL_URL = 'revoked'
				AND cct.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
			)
			OR (
				cct.FULL_CRL_URL = 'expired'
				AND x509_notAfter(c.CERTIFICATE) > now() AT TIME ZONE 'UTC'
			)
			OR EXISTS (
				SELECT 1
					FROM crl
					WHERE cac.CA_ID = crl.CA_ID
						AND cct.FULL_CRL_URL = crl.DISTRIBUTION_POINT_URL
						AND (
							(crl.ERROR_MESSAGE IS NOT NULL)
							OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
						)
			)
			OR EXISTS (
				SELECT 1
					FROM crl, json_array_elements_text(cct.JSON_ARRAY_OF_CRL_URLS::json) json_crl_url
					WHERE cac.CA_ID = crl.CA_ID
						AND length(cct.JSON_ARRAY_OF_CRL_URLS) > 4	-- Longer than [""].
						AND crl.DISTRIBUTION_POINT_URL = json_crl_url
						AND (
							(crl.ERROR_MESSAGE IS NOT NULL)
							OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
						)
			)
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosureIncomplete'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (
			(
				(coalesce(cct.CP_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(cct.CPS_URL, cct.CP_CPS_URL) IS NULL)
				OR (coalesce(coalesce(cct.CP_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (coalesce(coalesce(cct.CPS_LAST_UPDATED, cct.CP_CPS_LAST_UPDATED), '-infinity'::timestamp) < (now() AT TIME ZONE 'UTC' - interval '365 days'))
				OR (cct.STANDARD_AUDIT_URL IS NULL)
				OR (cct.STANDARD_AUDIT_TYPE IS NULL)
				OR (cct.STANDARD_AUDIT_DATE IS NULL)
				OR (cct.STANDARD_AUDIT_START IS NULL)
				OR (cct.STANDARD_AUDIT_END IS NULL)
				-- TODO: Uncomment these lines once every CA should have a Standalone NetSec audit.
/*				OR (cct.NETSEC_AUDIT_URL IS NULL)
				OR (cct.NETSEC_AUDIT_TYPE IS NULL)
				OR (cct.NETSEC_AUDIT_DATE IS NULL)
				OR (cct.NETSEC_AUDIT_START IS NULL)
				OR (cct.NETSEC_AUDIT_END IS NULL)*/
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 6
							AND ctp.TRUST_PURPOSE_ID = 1
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
				)
				AND (
					(cct.BRSSL_AUDIT_URL IS NULL)
					OR (cct.BRSSL_AUDIT_TYPE IS NULL)
					OR (cct.BRSSL_AUDIT_DATE IS NULL)
					OR (cct.BRSSL_AUDIT_START IS NULL)
					OR (cct.BRSSL_AUDIT_END IS NULL)
				)
			)
			OR (
				EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp, trust_purpose tp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 6
							AND ctp.TRUST_PURPOSE_ID >= 100
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND x509_isPolicyPermitted(c.CERTIFICATE, tp.PURPOSE_OID)
							AND (
								x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
								OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
							)
							AND ctp.IS_TIME_VALID
				)
				AND (
					(cct.EVSSL_AUDIT_URL IS NULL)
					OR (cct.EVSSL_AUDIT_TYPE IS NULL)
					OR (cct.EVSSL_AUDIT_DATE IS NULL)
					OR (cct.EVSSL_AUDIT_START IS NULL)
					OR (cct.EVSSL_AUDIT_END IS NULL)
				)
			)
		);

\echo Disclosed -> DisclosedWithInconsistentAudit
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY coalesce(nullif(cct2.SUBORDINATE_CA_OWNER, ''), cct2.CA_OWNER)
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Audit inconsistencies are only relevant if the CA is trusted by Mozilla.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.STANDARD_AUDIT_URL, cct2.STANDARD_AUDIT_TYPE, cct2.STANDARD_AUDIT_DATE, cct2.STANDARD_AUDIT_START, cct2.STANDARD_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Mozilla.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
-- TODO: Uncomment this UPDATE statement once every CA should have a Standalone NetSec audit.
/*UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.NETSEC_AUDIT_URL, cct2.NETSEC_AUDIT_TYPE, cct2.NETSEC_AUDIT_DATE, cct2.NETSEC_AUDIT_START, cct2.NETSEC_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- NetSec audit inconsistencies are only relevant if the CA is trusted by Mozilla.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;*/
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND ctp.TRUST_PURPOSE_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Mozilla to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.BRSSL_AUDIT_URL, cct2.BRSSL_AUDIT_TYPE, cct2.BRSSL_AUDIT_DATE, cct2.BRSSL_AUDIT_START, cct2.BRSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- BR SSL audit inconsistencies are only relevant if the CA is trusted by Mozilla to issue Server Authentication certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND ctp.TRUST_PURPOSE_ID >= 100
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Mozilla to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.EVSSL_AUDIT_URL, cct2.EVSSL_AUDIT_TYPE, cct2.EVSSL_AUDIT_DATE, cct2.EVSSL_AUDIT_START, cct2.EVSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- EV SSL audit inconsistencies are only relevant if the CA is trusted by Mozilla to issue EV SSL certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID >= 100
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND ctp.TRUST_PURPOSE_ID = 3
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Mozilla to issue S/MIME certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.SMIME_AUDIT_URL, cct2.SMIME_AUDIT_TYPE, cct2.SMIME_AUDIT_DATE, cct2.SMIME_AUDIT_START, cct2.SMIME_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- S/MIME audit inconsistencies are only relevant if the CA is trusted by Mozilla to issue S/MIME certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID = 3
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY coalesce(nullif(cct2.SUBORDINATE_CA_OWNER, ''), cct2.CA_OWNER)
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Audit inconsistencies are only relevant if the CA is trusted by Microsoft.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.STANDARD_AUDIT_URL, cct2.STANDARD_AUDIT_TYPE, cct2.STANDARD_AUDIT_DATE, cct2.STANDARD_AUDIT_START, cct2.STANDARD_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Microsoft.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
-- TODO: Uncomment this UPDATE statement once every CA should have a Standalone NetSec audit.
/*UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.NETSEC_AUDIT_URL, cct2.NETSEC_AUDIT_TYPE, cct2.NETSEC_AUDIT_DATE, cct2.NETSEC_AUDIT_START, cct2.NETSEC_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- NetSec audit inconsistencies are only relevant if the CA is trusted by Microsoft.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;*/
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND ctp.TRUST_PURPOSE_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Microsoft to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.BRSSL_AUDIT_URL, cct2.BRSSL_AUDIT_TYPE, cct2.BRSSL_AUDIT_DATE, cct2.BRSSL_AUDIT_START, cct2.BRSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- BR SSL audit inconsistencies are only relevant if the CA is trusted by Microsoft to issue Server Authentication certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND ctp.TRUST_PURPOSE_ID >= 100
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Microsoft to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.EVSSL_AUDIT_URL, cct2.EVSSL_AUDIT_TYPE, cct2.EVSSL_AUDIT_DATE, cct2.EVSSL_AUDIT_START, cct2.EVSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- EV SSL audit inconsistencies are only relevant if the CA is trusted by Microsoft to issue EV SSL certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID >= 100
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND ctp.TRUST_PURPOSE_ID = 3
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Microsoft to issue S/MIME certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.SMIME_AUDIT_URL, cct2.SMIME_AUDIT_TYPE, cct2.SMIME_AUDIT_DATE, cct2.SMIME_AUDIT_START, cct2.SMIME_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- S/MIME audit inconsistencies are only relevant if the CA is trusted by Microsoft to issue S/MIME certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID = 3
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND ctp.TRUST_PURPOSE_ID = 4
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Microsoft to issue Code Signing certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.3')
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.CODE_AUDIT_URL, cct2.CODE_AUDIT_TYPE, cct2.CODE_AUDIT_DATE, cct2.CODE_AUDIT_START, cct2.CODE_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Code Signing audit inconsistencies are only relevant if the CA is trusted by Microsoft to issue Code Signing certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND ctp.TRUST_PURPOSE_ID = 4
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY coalesce(nullif(cct2.SUBORDINATE_CA_OWNER, ''), cct2.CA_OWNER)
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Audit inconsistencies are only relevant if the CA is trusted by Apple.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.STANDARD_AUDIT_URL, cct2.STANDARD_AUDIT_TYPE, cct2.STANDARD_AUDIT_DATE, cct2.STANDARD_AUDIT_START, cct2.STANDARD_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Apple.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
-- TODO: Uncomment this UPDATE statement once every CA should have a Standalone NetSec audit.
/*UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.NETSEC_AUDIT_URL, cct2.NETSEC_AUDIT_TYPE, cct2.NETSEC_AUDIT_DATE, cct2.NETSEC_AUDIT_START, cct2.NETSEC_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- NetSec audit inconsistencies are only relevant if the CA is trusted by Apple.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;*/
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND ctp.TRUST_PURPOSE_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Apple to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.BRSSL_AUDIT_URL, cct2.BRSSL_AUDIT_TYPE, cct2.BRSSL_AUDIT_DATE, cct2.BRSSL_AUDIT_START, cct2.BRSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- BR SSL audit inconsistencies are only relevant if the CA is trusted by Apple to issue Server Authentication certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.TRUST_PURPOSE_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND ctp.TRUST_PURPOSE_ID >= 100
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Apple to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.EVSSL_AUDIT_URL, cct2.EVSSL_AUDIT_TYPE, cct2.EVSSL_AUDIT_DATE, cct2.EVSSL_AUDIT_START, cct2.EVSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- EV SSL audit inconsistencies are only relevant if the CA is trusted by Apple to issue EV SSL certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.TRUST_PURPOSE_ID >= 100
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND ctp.TRUST_PURPOSE_ID = 3
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Apple to issue S/MIME certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.SMIME_AUDIT_URL, cct2.SMIME_AUDIT_TYPE, cct2.SMIME_AUDIT_DATE, cct2.SMIME_AUDIT_START, cct2.SMIME_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- S/MIME audit inconsistencies are only relevant if the CA is trusted by Apple to issue S/MIME certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND ctp.TRUST_PURPOSE_ID = 3
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY coalesce(nullif(cct2.SUBORDINATE_CA_OWNER, ''), cct2.CA_OWNER)
					) sub
			) audit_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Audit inconsistencies are only relevant if the CA is trusted by Chrome.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.STANDARD_AUDIT_URL, cct2.STANDARD_AUDIT_TYPE, cct2.STANDARD_AUDIT_DATE, cct2.STANDARD_AUDIT_START, cct2.STANDARD_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Chrome.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
-- TODO: Uncomment this UPDATE statement once every CA should have a Standalone NetSec audit.
/*UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.NETSEC_AUDIT_URL, cct2.NETSEC_AUDIT_TYPE, cct2.NETSEC_AUDIT_DATE, cct2.NETSEC_AUDIT_START, cct2.NETSEC_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- NetSec audit inconsistencies are only relevant if the CA is trusted by Chrome.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;*/
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND ctp.TRUST_PURPOSE_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Chrome to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.BRSSL_AUDIT_URL, cct2.BRSSL_AUDIT_TYPE, cct2.BRSSL_AUDIT_DATE, cct2.BRSSL_AUDIT_START, cct2.BRSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- BR SSL audit inconsistencies are only relevant if the CA is trusted by Chrome to issue Server Authentication certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND ctp.TRUST_PURPOSE_ID = 1
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentAudit'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_AUDIT_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND ctp.TRUST_PURPOSE_ID >= 100
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)	-- Consider all Parent CAs that are trusted by Chrome to issue Server Authentication certificates.
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND (
									x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
									OR x509_isEKUPermitted(c2.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
									OR x509_isEKUPermitted(c2.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
								)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY cct2.EVSSL_AUDIT_URL, cct2.EVSSL_AUDIT_TYPE, cct2.EVSSL_AUDIT_DATE, cct2.EVSSL_AUDIT_START, cct2.EVSSL_AUDIT_END
					) sub
			) audit_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- EV SSL audit inconsistencies are only relevant if the CA is trusted by Chrome to issue EV SSL certificates.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND ctp.TRUST_PURPOSE_ID >= 100
		)
		AND coalesce(audit_variations.NUMBER_OF_AUDIT_VARIATIONS, 0) > 1;

\echo Disclosed -> DisclosedWithInconsistentCPS
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithInconsistentCPS'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_CP_CPS_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 5
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY sort_delimited_list(cct2.CP_URL, ';'), sort_delimited_list(cct2.CPS_URL, ';'), sort_delimited_list(cct2.CP_CPS_URL, ';')
					) sub
			) cpcps_variations ON TRUE
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Mozilla.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
		)
		AND coalesce(cpcps_variations.NUMBER_OF_CP_CPS_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithInconsistentCPS'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_CP_CPS_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 1
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND NOT is_technically_constrained(c2.CERTIFICATE)
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY sort_delimited_list(cct2.CP_URL, ';'), sort_delimited_list(cct2.CPS_URL, ';'), sort_delimited_list(cct2.CP_CPS_URL, ';')
					) sub
			) cpcps_variations ON TRUE
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Mozilla.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
		)
		AND coalesce(cpcps_variations.NUMBER_OF_CP_CPS_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithInconsistentCPS'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_CP_CPS_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 12
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY sort_delimited_list(cct2.CP_URL, ';'), sort_delimited_list(cct2.CPS_URL, ';'), sort_delimited_list(cct2.CP_CPS_URL, ';')
					) sub
			) cpcps_variations ON TRUE
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Apple.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
		)
		AND coalesce(cpcps_variations.NUMBER_OF_CP_CPS_VARIATIONS, 0) > 1;

UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithInconsistentCPS'
	FROM ca_certificate cac
			LEFT JOIN LATERAL (
				SELECT COUNT(*) AS NUMBER_OF_CP_CPS_VARIATIONS
					FROM (
						SELECT 1
							FROM ca_certificate cac2, ccadb_certificate_temp cct2, certificate c2
							WHERE cac.CA_ID = cac2.CA_ID
								AND EXISTS (
									SELECT 1
										FROM certificate c, ca_trust_purpose ctp
										WHERE c.ID = cac2.CERTIFICATE_ID
											AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
											AND c.ISSUER_CA_ID = ctp.CA_ID
											AND ctp.TRUST_CONTEXT_ID = 6
											AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
											AND ctp.IS_TIME_VALID
								)
								AND cac2.CERTIFICATE_ID = cct2.CERTIFICATE_ID
								AND cct2.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked')
								AND cct2.CERTIFICATE_ID = c2.ID
								AND cct2.CCADB_RECORD_ID IS NOT NULL	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
							GROUP BY sort_delimited_list(cct2.CP_URL, ';'), sort_delimited_list(cct2.CPS_URL, ';'), sort_delimited_list(cct2.CP_CPS_URL, ';')
					) sub
			) cpcps_variations ON TRUE
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
		AND EXISTS (			-- Standard audit inconsistencies are only relevant if the CA is trusted by Chrome.
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = cac.CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
		)
		AND coalesce(cpcps_variations.NUMBER_OF_CP_CPS_VARIATIONS, 0) > 1;

\echo DisclosureIncomplete, DisclosedWithInconsistentAudit, DisclosedWithInconsistentCPS -> AllSuitablePathsRevoked
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS IN ('DisclosureIncomplete', 'DisclosedWithInconsistentAudit', 'DisclosedWithInconsistentCPS')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 5
					AND ctp.TRUST_PURPOSE_ID IN (1, 3)
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS IN ('DisclosureIncomplete', 'DisclosedWithInconsistentAudit', 'DisclosedWithInconsistentCPS')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 1
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS IN ('DisclosureIncomplete', 'DisclosedWithInconsistentAudit', 'DisclosedWithInconsistentCPS')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 12
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'AllSuitablePathsRevoked'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS IN ('DisclosureIncomplete', 'DisclosedWithInconsistentAudit', 'DisclosedWithInconsistentCPS')
		AND cct.CERTIFICATE_ID = c.ID
		AND NOT EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = c.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = 6
					AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
		);

\echo Disclosed -> DisclosedWithErrors
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedWithErrors'
	FROM certificate c
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'commonName') || '%')
		AND (cct.PARENT_CERT_NAME NOT LIKE get_ca_name_attribute(c.ISSUER_CA_ID, 'organizationName') || '%');

\echo Disclosed -> DisclosedButInCRL
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedButInCRL'
	FROM certificate c, crl_revoked cr
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedButInCRL'
	FROM certificate c, crl_revoked cr
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID;
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedButInCRL'
	FROM certificate c, crl_revoked cr
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERT_RECORD_TYPE != 'Root Certificate'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID;
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedButInCRL'
	FROM certificate c, crl_revoked cr
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'Disclosed'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID;

\echo DisclosedButInCRL -> DisclosedButRemovedFromCRL
UPDATE ccadb_certificate_temp cct
	SET MOZILLA_DISCLOSURE_STATUS = 'DisclosedButRemovedFromCRL'
	FROM certificate c, crl_revoked cr, crl
	WHERE cct.MOZILLA_DISCLOSURE_STATUS = 'DisclosedButInCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID
		AND cr.CA_ID = crl.CA_ID
		AND crl.THIS_UPDATE > cr.LAST_SEEN_CHECK_DATE;
UPDATE ccadb_certificate_temp cct
	SET MICROSOFT_DISCLOSURE_STATUS = 'DisclosedButRemovedFromCRL'
	FROM certificate c, crl_revoked cr, crl
	WHERE cct.MICROSOFT_DISCLOSURE_STATUS = 'DisclosedButInCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID
		AND cr.CA_ID = crl.CA_ID
		AND crl.THIS_UPDATE > cr.LAST_SEEN_CHECK_DATE;
UPDATE ccadb_certificate_temp cct
	SET APPLE_DISCLOSURE_STATUS = 'DisclosedButRemovedFromCRL'
	FROM certificate c, crl_revoked cr, crl
	WHERE cct.APPLE_DISCLOSURE_STATUS = 'DisclosedButInCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID
		AND cr.CA_ID = crl.CA_ID
		AND crl.THIS_UPDATE > cr.LAST_SEEN_CHECK_DATE;
UPDATE ccadb_certificate_temp cct
	SET CHROME_DISCLOSURE_STATUS = 'DisclosedButRemovedFromCRL'
	FROM certificate c, crl_revoked cr, crl
	WHERE cct.CHROME_DISCLOSURE_STATUS = 'DisclosedButInCRL'
		AND cct.CERTIFICATE_ID = c.ID
		AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
		AND c.ISSUER_CA_ID = cr.CA_ID
		AND cr.CA_ID = crl.CA_ID
		AND crl.THIS_UPDATE > cr.LAST_SEEN_CHECK_DATE;


\echo Tidying Up

ANALYZE ccadb_certificate_temp;

UPDATE ccadb_certificate_temp cct
	SET LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE = cc.LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256
		AND cct.MOZILLA_DISCLOSURE_STATUS = cc.MOZILLA_DISCLOSURE_STATUS
		AND cc.LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE IS NOT NULL;
UPDATE ccadb_certificate_temp cct
	SET LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE = cc.LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256
		AND cct.MICROSOFT_DISCLOSURE_STATUS = cc.MICROSOFT_DISCLOSURE_STATUS
		AND cc.LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE IS NOT NULL;
UPDATE ccadb_certificate_temp cct
	SET LAST_APPLE_DISCLOSURE_STATUS_CHANGE = cc.LAST_APPLE_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256
		AND cct.APPLE_DISCLOSURE_STATUS = cc.APPLE_DISCLOSURE_STATUS
		AND cc.LAST_APPLE_DISCLOSURE_STATUS_CHANGE IS NOT NULL;
UPDATE ccadb_certificate_temp cct
	SET LAST_CHROME_DISCLOSURE_STATUS_CHANGE = cc.LAST_CHROME_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256
		AND cct.CHROME_DISCLOSURE_STATUS = cc.CHROME_DISCLOSURE_STATUS
		AND cc.LAST_CHROME_DISCLOSURE_STATUS_CHANGE IS NOT NULL;
UPDATE ccadb_certificate_temp cct
	SET TEST_WEBSITE_VALID_STATUS = cc.TEST_WEBSITE_VALID_STATUS,
		TEST_WEBSITE_EXPIRED_STATUS = cc.TEST_WEBSITE_EXPIRED_STATUS,
		TEST_WEBSITE_REVOKED_STATUS = cc.TEST_WEBSITE_REVOKED_STATUS,
		TEST_WEBSITE_VALID_CERTIFICATE_ID = cc.TEST_WEBSITE_VALID_CERTIFICATE_ID,
		TEST_WEBSITE_EXPIRED_CERTIFICATE_ID = cc.TEST_WEBSITE_EXPIRED_CERTIFICATE_ID,
		TEST_WEBSITE_REVOKED_CERTIFICATE_ID = cc.TEST_WEBSITE_REVOKED_CERTIFICATE_ID,
		TEST_WEBSITES_CHECKED = 'f'
	FROM ccadb_certificate cc
	WHERE cct.CERT_SHA256 = cc.CERT_SHA256;

INSERT INTO crl (
		CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
	)
	SELECT cac.CA_ID, cct.FULL_CRL_URL, now() AT TIME ZONE 'UTC', TRUE
		FROM ccadb_certificate_temp cct, ca_certificate cac
		WHERE nullif(nullif(nullif(cct.FULL_CRL_URL, ''), 'revoked'), 'expired') IS NOT NULL
			AND cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
			AND NOT EXISTS (
				SELECT 1
					FROM crl
					WHERE crl.CA_ID = cac.CA_ID
						AND crl.DISTRIBUTION_POINT_URL = cct.FULL_CRL_URL
			)
		GROUP BY cac.CA_ID, cct.FULL_CRL_URL;

INSERT INTO crl (
		CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
	)
	SELECT cac.CA_ID, json_crl_url, now() AT TIME ZONE 'UTC', TRUE
		FROM ccadb_certificate_temp cct, ca_certificate cac, json_array_elements_text(cct.JSON_ARRAY_OF_CRL_URLS::json) json_crl_url
		WHERE cct.CERTIFICATE_ID = cac.CERTIFICATE_ID
			AND length(cct.JSON_ARRAY_OF_CRL_URLS) > 4	-- Longer than [""].
			AND NOT EXISTS (
				SELECT 1
					FROM crl
					WHERE crl.CA_ID = cac.CA_ID
						AND crl.DISTRIBUTION_POINT_URL = json_crl_url
			)
		GROUP BY cac.CA_ID, json_crl_url;

COMMIT WORK;


BEGIN WORK;

LOCK ccadb_certificate;

TRUNCATE ccadb_certificate;

INSERT INTO ccadb_certificate
	SELECT *
		FROM ccadb_certificate_temp;

COMMIT WORK;


SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-disclosures,0}'::text[]), 1, 6);

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{microsoft-disclosures,0}'::text[]), 1, 6);

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{apple-disclosures,0}'::text[]), 1, 6);

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{chrome-disclosures,0}'::text[]), 1, 6);
