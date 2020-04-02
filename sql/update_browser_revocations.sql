\timing

\set ON_ERROR_STOP on


-- Note: The microsoft_disallowedcert table is updated manually.


-- Update the mozilla_onecrl table.

BEGIN WORK;

CREATE TEMPORARY TABLE onecrl_import1 (
	ONECRL_DATA	JSON
) ON COMMIT DROP;

\COPY onecrl_import1 FROM 'onecrl.json';

CREATE TEMPORARY TABLE onecrl_import2 ON COMMIT DROP AS
SELECT json_array_elements((o.onecrl_data->>'data')::json) CERT_ITEM
	FROM onecrl_import1 o;

CREATE TEMPORARY TABLE onecrl_import3 ON COMMIT DROP AS
SELECT decode(
			o.CERT_ITEM->>'issuerName'
				|| CASE length(o.CERT_ITEM->>'issuerName') % 4
					WHEN 2 THEN '=='
					WHEN 3 THEN '='
					ELSE ''
				END,
			'base64'
		) ISSUER_NAME,
		timestamp without time zone 'epoch'
			+ ((o.CERT_ITEM->>'last_modified')::bigint * interval '1 millisecond') LAST_MODIFIED,
		decode(
			o.CERT_ITEM->>'serialNumber'
				|| CASE length(o.CERT_ITEM->>'serialNumber') % 4
					WHEN 2 THEN '=='
					WHEN 3 THEN '='
					ELSE ''
				END,
			'base64'
		) SERIAL_NUMBER,
		CASE WHEN coalesce((((o.CERT_ITEM->>'details')::json)->>'created'), '') = ''
			THEN NULL
			ELSE (((o.CERT_ITEM->>'details')::json)->>'created')::timestamp
		END CREATED,
		((o.CERT_ITEM->>'details')::json)->>'bug' BUG_URL,
		((o.CERT_ITEM->>'details')::json)->>'name' SUMMARY
	FROM onecrl_import2 o;

CREATE TEMPORARY TABLE mozilla_onecrl_new ON COMMIT DROP AS
SELECT c.ID		CERTIFICATE_ID,
		c.ISSUER_CA_ID,
		o.*,
		x509_name(c.CERTIFICATE, TRUE) SUBJECT_NAME,
		x509_notAfter(c.CERTIFICATE) NOT_AFTER
	FROM onecrl_import3 o
		LEFT OUTER JOIN certificate c ON (
			o.SERIAL_NUMBER = x509_serialNumber(c.CERTIFICATE)
			AND o.ISSUER_NAME = x509_name(c.CERTIFICATE, 'f')
		);

UPDATE mozilla_onecrl_new mon
	SET ISSUER_CA_ID = ca.ID
	FROM ca
	WHERE ca.NAME = x509_name_print(mon.ISSUER_NAME)
		AND mon.ISSUER_CA_ID IS NULL;

LOCK mozilla_onecrl;

TRUNCATE mozilla_onecrl;

INSERT INTO mozilla_onecrl
	SELECT *
		FROM mozilla_onecrl_new;

COMMIT WORK;

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{mozilla-onecrl,0}'::text[]), 1, 6);

SELECT substr(web_apis(NULL, '{output,maxage}'::text[], '{revoked-intermediates,0}'::text[]), 1, 6);


-- Update the google_revoked table.

BEGIN WORK;

LOCK google_crlset_import;

TRUNCATE google_crlset_import;

\COPY google_crlset_import FROM 'google_crlset.csv';

LOCK google_revoked;

TRUNCATE google_revoked;

INSERT INTO google_revoked (CERTIFICATE_ID, ENTRY_TYPE)
	SELECT c.ID, 'Serial Number'::revocation_entry_type
		FROM google_crlset_import gci, certificate c, ca
		WHERE gci.SERIAL_NUMBER = x509_serialNumber(c.CERTIFICATE)
			AND gci.ISSUER_SPKI_SHA256 = digest(ca.PUBLIC_KEY, 'sha256')
			AND gci.SPKI_SHA256 = E'\\x'
			AND c.ISSUER_CA_ID = ca.ID
	UNION
	SELECT c.ID, 'SHA-256(SubjectPublicKeyInfo)'::revocation_entry_type
		FROM google_crlset_import gci, certificate c, ca
		WHERE gci.SERIAL_NUMBER = E'\\x'
			AND gci.ISSUER_SPKI_SHA256 = E'\\x'
			AND gci.SPKI_SHA256 = digest(x509_publicKey(c.CERTIFICATE), 'sha256')
	UNION
	SELECT c.ID, gbi.ENTRY_TYPE
		FROM google_blacklist_import gbi, certificate c
		WHERE ((gbi.ENTRY_TYPE = 'SHA-256(Certificate)') AND (gbi.ENTRY_SHA256 = digest(c.CERTIFICATE, 'sha256')))
			OR ((gbi.ENTRY_TYPE = 'SHA-256(SubjectPublicKeyInfo)') AND (gbi.ENTRY_SHA256 = digest(x509_publickey(c.CERTIFICATE), 'sha256')));

COMMIT WORK;
