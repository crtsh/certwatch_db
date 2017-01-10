/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2016 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

CREATE OR REPLACE FUNCTION import_cert(
	cert_data				bytea
) RETURNS certificate.ID%TYPE
AS $$
DECLARE
	t_certificateID		certificate.ID%TYPE;
	t_verified			boolean							:= FALSE;
	t_canIssueCerts		boolean;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE	:= -1;
	t_name				ca.NAME%TYPE;
	t_brand				ca.BRAND%TYPE;
	t_publicKey			ca.PUBLIC_KEY%TYPE;
	t_caID				ca.ID%TYPE;
	t_lintingApplies	ca.LINTING_APPLIES%TYPE			:= TRUE;
	l_ca				RECORD;
	l_cdp				RECORD;
BEGIN
	IF cert_data IS NULL THEN
		RETURN NULL;
	END IF;

	SELECT c.ID
		INTO t_certificateID
		FROM certificate c
		WHERE digest(c.CERTIFICATE, 'sha256')
					= digest(cert_data, 'sha256');
	IF t_certificateID IS NOT NULL THEN
		RETURN t_certificateID;
	END IF;

	t_canIssueCerts := x509_canIssueCerts(cert_data);
	IF t_canIssueCerts THEN
		t_name := x509_subjectName(cert_data);
		t_publicKey := x509_publicKey(cert_data);
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
					NAME, PUBLIC_KEY, BRAND
				)
				VALUES (
					t_name, t_publicKey, t_brand
				)
				RETURNING ca.ID
					INTO t_caID;
		END IF;
	END IF;

	FOR l_ca IN (
				SELECT *
					FROM ca
					WHERE ca.NAME = x509_issuerName(cert_data)
						AND ca.PUBLIC_KEY != E'\\x00'
					ORDER BY octet_length(PUBLIC_KEY) DESC
			) LOOP
		IF x509_verify(cert_data, l_ca.PUBLIC_KEY) THEN
			t_issuerCAID := l_ca.ID;
			t_lintingApplies := l_ca.LINTING_APPLIES;
			t_verified := TRUE;
			EXIT;
		END IF;
	END LOOP;

	IF NOT t_verified THEN
		SELECT ic.CERTIFICATE_ID
			INTO t_certificateID
			FROM invalid_certificate ic
			WHERE ic.CERTIFICATE_AS_LOGGED = cert_data;
		t_verified := FOUND;
	END IF;

	IF t_certificateID IS NULL THEN
		INSERT INTO certificate (
				CERTIFICATE, ISSUER_CA_ID
			)
			VALUES (
				cert_data, t_issuerCAID
			)
			RETURNING ID
				INTO t_certificateID;
	END IF;

	IF (NOT t_verified) AND (t_issuerCAID != -1) THEN
		INSERT INTO invalid_certificate (
				CERTIFICATE_ID
			)
			VALUES (
				t_certificateID
			);
	END IF;

	UPDATE ca
		SET NO_OF_CERTS_ISSUED = NO_OF_CERTS_ISSUED + 1
		WHERE ID = t_issuerCAID;

	PERFORM extract_cert_names(t_certificateID, t_issuerCAID);

	IF t_canIssueCerts THEN
		INSERT INTO ca_certificate (
				CERTIFICATE_ID, CA_ID
			)
			VALUES (
				t_certificateID, t_caID
			);

		IF NOT t_lintingApplies THEN
			UPDATE ca
				SET LINTING_APPLIES = FALSE
				WHERE ID = t_caID;
		END IF;
	END IF;

	IF t_lintingApplies THEN
		PERFORM lint_cached(t_certificateID, 'x509lint');
	END IF;

	FOR l_cdp IN (
				SELECT x509_crlDistributionPoints(cert_data) URL
			) LOOP
		INSERT INTO crl (
				CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
			)
			VALUES (
				t_issuerCAID, trim(l_cdp.URL), statement_timestamp(), TRUE
			)
			ON CONFLICT DO NOTHING;
	END LOOP;

	RETURN t_certificateID;

EXCEPTION
	WHEN others THEN
		RETURN NULL;
END;
$$ LANGUAGE plpgsql;
