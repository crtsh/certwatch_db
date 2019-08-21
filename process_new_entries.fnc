CREATE OR REPLACE FUNCTION process_new_entries(
) RETURNS void
AS $$
DECLARE
	caCert_cursor		CURSOR FOR
							SELECT x509_subjectName(net.DER_X509) SUBJECT_NAME,
									x509_publicKey(net.DER_X509) PUBLIC_KEY,
									NULL::text BRAND
								FROM newentries_temp net
								WHERE net.NEW_AND_CAN_ISSUE_CERTS
								FOR UPDATE;
	findIssuer_cursor	CURSOR FOR
							SELECT net.CT_LOG_ID, net.ENTRY_ID, net.ENTRY_TIMESTAMP,
									net.DER_X509, net.CERTIFICATE_ID,
									net.ISSUER_CA_ID, NULL::boolean LINTING_APPLIES,
									net.NEW_AND_CAN_ISSUE_CERTS
								FROM newentries_temp net
								WHERE net.NEW_CERT_COUNT = 1
									AND net.ISSUER_CA_ID IS NULL
								FOR UPDATE;

	t_caID				ca.ID%TYPE;
	l_ca				RECORD;
	t_now				timestamp;
	t_isNewCA			boolean;
BEGIN
	-- Linting requirements flow down from the issuer CA.
	UPDATE newentries_temp net
		SET LINTING_APPLIES = 't'
		FROM ca
		WHERE net.ISSUER_CA_ID IS NOT NULL
			AND net.ISSUER_CA_ID = ca.ID
			AND ca.LINTING_APPLIES = 't';

	-- Determine which certificates are already known.
	UPDATE newentries_temp net
		SET CERTIFICATE_ID = c.ID,
			NEW_CERT_COUNT = 0
		FROM certificate c
		WHERE net.SHA256_X509 = digest(c.CERTIFICATE, 'sha256');

	-- Assign IDs for the certificates that are new.
	UPDATE newentries_temp net
		SET CERTIFICATE_ID = sub.NEW_CERTIFICATE_ID,
			NEW_AND_CAN_ISSUE_CERTS = x509_canIssueCerts(net.DER_X509)
		FROM (
				SELECT net2.SHA256_X509,
						nextval('certificate_id_seq'::regclass) NEW_CERTIFICATE_ID
					FROM newentries_temp net2
					WHERE net2.NEW_CERT_COUNT = 1
					GROUP BY net2.SHA256_X509
			) sub
		WHERE net.SHA256_X509 = sub.SHA256_X509;

	-- If this is a CA certificate, find (or create) the Subject CA record.
	FOR l_caCert IN caCert_cursor LOOP
		IF l_caCert.PUBLIC_KEY IS NULL THEN
			l_caCert.BRAND := 'Bad Public Key';
			l_caCert.PUBLIC_KEY := E'\\x00';
		END IF;

		t_isNewCA := FALSE;
		SELECT ca.ID
			INTO t_caID
			FROM ca
			WHERE ca.NAME = l_caCert.SUBJECT_NAME
				AND ca.PUBLIC_KEY IN (l_caCert.PUBLIC_KEY, E'\\x00');
		IF t_caID IS NULL THEN
			INSERT INTO ca (
					NAME, PUBLIC_KEY, LINTING_APPLIES, BRAND
				)
				VALUES (
					l_caCert.SUBJECT_NAME, l_caCert.PUBLIC_KEY, 't', l_caCert.BRAND
				)
				RETURNING ca.ID
					INTO t_caID;
			t_isNewCA := TRUE;
		END IF;
		UPDATE newentries_temp
			SET SUBJECT_CA_ID = t_caID,
				IS_NEW_CA = t_isNewCA
			WHERE CURRENT OF caCert_cursor;
	END LOOP;

	FOR l_entry IN findIssuer_cursor LOOP
		-- The ct_monitor Go code was unable to determine the CA ID.
		-- Have another go, just in case libx509pq/OpenSSL can do better.
		FOR l_ca IN (
					SELECT ca.ID, ca.LINTING_APPLIES, ca.PUBLIC_KEY
						FROM ca
						WHERE ca.NAME = x509_issuerName(l_entry.DER_X509)
							AND ca.PUBLIC_KEY != E'\\x00'
						ORDER BY octet_length(ca.PUBLIC_KEY) DESC
				) LOOP
			IF x509_verify(l_entry.DER_X509, l_ca.PUBLIC_KEY) THEN
				l_entry.ISSUER_CA_ID := l_ca.ID;
				l_entry.LINTING_APPLIES := l_ca.LINTING_APPLIES;
				EXIT;
			END IF;
		END LOOP;

		UPDATE newentries_temp net
			SET ISSUER_CA_ID = coalesce(l_entry.ISSUER_CA_ID, -1),
				LINTING_APPLIES = coalesce(l_entry.LINTING_APPLIES, 't')
			WHERE CURRENT OF findIssuer_cursor;
	END LOOP;

	t_now := statement_timestamp() AT TIME ZONE 'UTC';
	INSERT INTO certificate (
			ID, CERTIFICATE, ISSUER_CA_ID,
			CABLINT_CACHED_AT,
			X509LINT_CACHED_AT,
			ZLINT_CACHED_AT
		)
		SELECT net.CERTIFICATE_ID, net.DER_X509, net.ISSUER_CA_ID,
				CASE WHEN bool_or(net.LINTING_APPLIES) THEN t_now ELSE NULL END,
				CASE WHEN bool_or(net.LINTING_APPLIES) THEN t_now ELSE NULL END,
				CASE WHEN bool_or(net.LINTING_APPLIES) THEN t_now ELSE NULL END
			FROM newentries_temp net
			WHERE net.NEW_CERT_COUNT = 1
			GROUP BY net.CERTIFICATE_ID, net.DER_X509, net.ISSUER_CA_ID;

	INSERT INTO ca_certificate (
			CERTIFICATE_ID, CA_ID
		)
		SELECT net.CERTIFICATE_ID, net.SUBJECT_CA_ID
			FROM newentries_temp net
			WHERE net.NEW_AND_CAN_ISSUE_CERTS;

	INSERT INTO ct_log_entry (
			CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID, ENTRY_TIMESTAMP
		)
		SELECT net.CERTIFICATE_ID, net.CT_LOG_ID, net.ENTRY_ID, net.ENTRY_TIMESTAMP
			FROM newentries_temp net;

	INSERT INTO certificate_identity (
			CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
		)
		SELECT net.CERTIFICATE_ID,
				max(net.ISSUER_CA_ID),
				sub.NAME_TYPE::name_type,
				min(encode(sub.RAW_VALUE, 'escape')) NAME_VALUE
			FROM newentries_temp net
					LEFT JOIN LATERAL (
						SELECT CASE x.ATTRIBUTE_OID
									WHEN '2.5.4.3' THEN 'commonName'
									WHEN '2.5.4.10' THEN 'organizationName'
									WHEN '2.5.4.11' THEN 'organizationalUnitName'
									WHEN '1.2.840.113549.1.9.1' THEN 'emailAddress'
									ELSE NULL
								END NAME_TYPE,
								x.RAW_VALUE
							FROM x509_nameAttributes_raw(net.DER_X509, 't') x
						UNION
						SELECT CASE x.TYPE_NUM
									WHEN '1' THEN 'rfc822Name'
									WHEN '2' THEN 'dNSName'
									WHEN '7' THEN 'iPAddress'
									ELSE NULL
								END NAME_TYPE,
								x.RAW_VALUE
							FROM x509_altNames_raw(net.DER_X509, 't') x
				) sub ON TRUE
			WHERE net.NEW_CERT_COUNT = 1
				AND sub.NAME_TYPE IS NOT NULL
			GROUP BY net.CERTIFICATE_ID, NAME_TYPE, lower(encode(sub.RAW_VALUE, 'escape'));

	PERFORM lint_new_cert(net.ISSUER_CA_ID, net.CERTIFICATE_ID::integer, 0, net.DER_X509, 'cablint'),
			lint_new_cert(
				net.ISSUER_CA_ID,
				net.CERTIFICATE_ID::integer,
				CASE WHEN net.SUBJECT_CA_ID IS NULL THEN 0
					WHEN net.SUBJECT_CA_ID = net.ISSUER_CA_ID THEN 2
					ELSE 1
				END,
				net.DER_X509,
				'x509lint'
			),
			lint_new_cert(net.ISSUER_CA_ID, net.CERTIFICATE_ID::integer, 0, net.DER_X509, 'zlint')
		FROM newentries_temp net
		WHERE net.NEW_CERT_COUNT = 1
			AND net.LINTING_APPLIES;

	UPDATE ca
		SET LINTING_APPLIES = 'f'
		FROM newentries_temp net
		WHERE net.IS_NEW_CA
			AND NOT net.LINTING_APPLIES
			AND net.SUBJECT_CA_ID = ca.ID;

	UPDATE ca
		SET NO_OF_CERTS_ISSUED = NO_OF_CERTS_ISSUED + sub.NEW_CERT_COUNT
		FROM (
			SELECT net.ISSUER_CA_ID, sum(net.NEW_CERT_COUNT) NEW_CERT_COUNT
				FROM newentries_temp net
				GROUP BY net.ISSUER_CA_ID
				HAVING sum(net.NEW_CERT_COUNT) > 0
			) sub
		WHERE ca.ID = sub.ISSUER_CA_ID;

	INSERT INTO crl (
			CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
		)
		SELECT sub.ISSUER_CA_ID, sub.DISTRIBUTION_POINT_URL, statement_timestamp() AT TIME ZONE 'UTC', TRUE
			FROM (
					SELECT net.ISSUER_CA_ID, trim(x509_crlDistributionPoints(net.DER_X509)) DISTRIBUTION_POINT_URL
						FROM newentries_temp net
						WHERE net.NEW_CERT_COUNT = 1
						GROUP BY net.ISSUER_CA_ID, DISTRIBUTION_POINT_URL
				) sub
			WHERE NOT EXISTS (
				SELECT 1
					FROM crl
					WHERE crl.CA_ID = sub.ISSUER_CA_ID
						AND crl.DISTRIBUTION_POINT_URL = sub.DISTRIBUTION_POINT_URL
			);

	INSERT INTO ocsp_responder (
			CA_ID, URL, NEXT_CHECKS_DUE
		)
		SELECT sub.ISSUER_CA_ID, sub.URL, statement_timestamp() AT TIME ZONE 'UTC'
			FROM (
					SELECT net.ISSUER_CA_ID, trim(x509_authorityInfoAccess(net.DER_X509, 1)) URL
						FROM newentries_temp net
						WHERE net.NEW_CERT_COUNT = 1
						GROUP BY net.ISSUER_CA_ID, URL
				) sub
			WHERE NOT EXISTS (
				SELECT 1
					FROM ocsp_responder ors
					WHERE ors.CA_ID = sub.ISSUER_CA_ID
						AND ors.URL = sub.URL
			);
END;
$$ LANGUAGE plpgsql;
