CREATE OR REPLACE FUNCTION import_chain_cert(
	ca_cert_data			bytea,
	issuer_ca_id			certificate.ISSUER_CA_ID%TYPE
) RETURNS ca.ID%TYPE
AS $$
DECLARE
	t_certificateID		certificate.ID%TYPE;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE	:= -1;
	t_name				ca.NAME%TYPE;
	t_brand				ca.BRAND%TYPE;
	t_publicKey			ca.PUBLIC_KEY%TYPE;
	t_caID				ca.ID%TYPE;
	t_is_new_ca			boolean							:= FALSE;
	t_lintingApplies	ca.LINTING_APPLIES%TYPE			:= TRUE;
	l_ca				RECORD;
	l_cdp				RECORD;
	l_aiaOCSP			RECORD;
BEGIN
	IF ca_cert_data IS NULL THEN
		RETURN NULL;
	END IF;

	SELECT c.ID, cac.CA_ID
		INTO t_certificateID, t_caID
		FROM certificate c
				LEFT OUTER JOIN ca_certificate cac ON (
					c.ID = cac.CERTIFICATE_ID
				)
		WHERE digest(c.CERTIFICATE, 'sha256')
					= digest(ca_cert_data, 'sha256');
	IF t_caID IS NOT NULL THEN
		RETURN t_caID;
	ELSE
		t_name := x509_subjectName(ca_cert_data);
		t_publicKey := x509_publicKey(ca_cert_data);
		IF t_publicKey IS NULL THEN
			t_brand := 'Bad Public Key';
			t_publicKey := E'\\x00';
		END IF;

		SELECT ca.ID
			INTO t_caID
			FROM ca
			WHERE ca.NAME = t_name
				AND ca.PUBLIC_KEY IN (t_publicKey, E'\\x00');
		IF t_caID IS NULL THEN
			INSERT INTO ca (
					NAME, PUBLIC_KEY, LINTING_APPLIES, BRAND
				)
				VALUES (
					t_name, t_publicKey, t_lintingApplies, t_brand
				)
				RETURNING ca.ID
					INTO t_caID;
			t_is_new_ca := TRUE;
		END IF;
	END IF;

	IF t_certificateID IS NULL THEN
		IF issuer_ca_id IS NOT NULL THEN
			SELECT ca.ID, ca.LINTING_APPLIES
				INTO t_issuerCAID, t_lintingApplies
				FROM ca
				WHERE ca.ID = issuer_ca_id;
			IF NOT FOUND THEN
				RAISE no_data_found;
			END IF;
		ELSE
			FOR l_ca IN (
						SELECT *
							FROM ca
							WHERE ca.NAME = x509_issuerName(ca_cert_data)
								AND ca.PUBLIC_KEY != E'\\x00'
							ORDER BY octet_length(PUBLIC_KEY) DESC
					) LOOP
				IF x509_verify(ca_cert_data, l_ca.PUBLIC_KEY) THEN
					t_issuerCAID := l_ca.ID;
					t_lintingApplies := l_ca.LINTING_APPLIES;
					EXIT;
				END IF;
			END LOOP;
		END IF;

		INSERT INTO certificate (
				CERTIFICATE, ISSUER_CA_ID
			)
			VALUES (
				ca_cert_data, t_issuerCAID
			)
			RETURNING ID
				INTO t_certificateID;

		UPDATE ca
			SET NO_OF_CERTS_ISSUED = NO_OF_CERTS_ISSUED + 1
			WHERE ID = t_issuerCAID;

		PERFORM extract_cert_names(t_certificateID, t_issuerCAID);

		IF t_lintingApplies THEN
			PERFORM lint_cached(t_certificateID, 'cablint');
			PERFORM lint_cached(t_certificateID, 'x509lint');
			PERFORM lint_cached(t_certificateID, 'zlint');
		END IF;

		FOR l_cdp IN (
					SELECT x509_crlDistributionPoints(ca_cert_data) URL
				) LOOP
			INSERT INTO crl (
					CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
				)
				VALUES (
					t_issuerCAID, trim(l_cdp.URL), statement_timestamp() AT TIME ZONE 'UTC', TRUE
				)
				ON CONFLICT DO NOTHING;
		END LOOP;

		FOR l_aiaOCSP IN (
					SELECT x509_authorityInfoAccess(ca_cert_data, 1) URL
				) LOOP
			INSERT INTO ocsp_responder (
					CA_ID, URL, NEXT_CHECKS_DUE
				)
				VALUES (
					t_issuerCAID, l_aiaOCSP.URL, statement_timestamp() AT TIME ZONE 'UTC'
				)
				ON CONFLICT DO NOTHING;
		END LOOP;
	END IF;

	INSERT INTO ca_certificate (
			CERTIFICATE_ID, CA_ID
		)
		VALUES (
			t_certificateID, t_caID
		);

	IF t_is_new_ca AND (NOT t_lintingApplies) THEN
		UPDATE ca
			SET LINTING_APPLIES = 'f'
			WHERE ca.ID = t_caID;
	END IF;

	RETURN t_caID;
END;
$$ LANGUAGE plpgsql;
