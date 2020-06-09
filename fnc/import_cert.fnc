/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2020 Sectigo Limited
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
	t_notAfter			timestamp;
	t_certificateID		certificate.ID%TYPE;
	t_verified			boolean							:= FALSE;
	t_canIssueCerts		boolean;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE	:= -1;
	t_name				ca.NAME%TYPE;
	t_publicKey			ca.PUBLIC_KEY%TYPE;
	t_caID				ca.ID%TYPE;
	t_lintingApplies	ca.LINTING_APPLIES%TYPE			:= TRUE;
	t_countIndex		smallint						:= 1;		-- Certificate.
	l_ca				RECORD;
	l_cdp				RECORD;
	l_aiaOCSP			RECORD;
	l_aiaCAIssuer		RECORD;
BEGIN
	IF cert_data IS NULL THEN
		RETURN NULL;
	END IF;

	t_notAfter := coalesce(x509_notAfter(cert_data), 'infinity'::timestamp);

	SELECT c.ID
		INTO t_certificateID
		FROM certificate c
		WHERE digest(cert_data, 'sha256') = digest(c.CERTIFICATE, 'sha256')
			AND t_notAfter = coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp);
	IF t_certificateID IS NOT NULL THEN
		RETURN t_certificateID;
	END IF;

	t_canIssueCerts := x509_canIssueCerts(cert_data);
	IF t_canIssueCerts THEN
		t_name := x509_subjectName(cert_data);
		t_publicKey := x509_publicKey(cert_data);
		IF t_publicKey IS NULL THEN
			t_publicKey := E'\\x00';
		END IF;

		SELECT ca.ID
			INTO t_caID
			FROM ca
			WHERE ca.NAME = t_name
				AND ca.PUBLIC_KEY IN (t_publicKey, E'\\x00');
		IF t_caID IS NULL THEN
			INSERT INTO ca (
					NAME, PUBLIC_KEY
				)
				VALUES (
					t_name, t_publicKey
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

	IF x509_hasExtension(cert_data, '1.3.6.1.4.1.11129.2.4.3', TRUE) THEN
		t_countIndex := 2;		-- Precertificate (RFC6962).
	END IF;
	UPDATE ca
		SET NUM_ISSUED[t_countIndex] = coalesce(NUM_ISSUED[t_countIndex], 0) + 1,
			NUM_EXPIRED[t_countIndex] = coalesce(NUM_EXPIRED[t_countIndex], 0) + CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN 1 ELSE 0 END,
			NEXT_NOT_AFTER = CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN NEXT_NOT_AFTER ELSE least(coalesce(NEXT_NOT_AFTER, 'infinity'::timestamp), t_notAfter) END
		WHERE ID = t_issuerCAID;

	IF t_canIssueCerts THEN
		BEGIN
			INSERT INTO ca_certificate (
					CERTIFICATE_ID, CA_ID
				)
				VALUES (
					t_certificateID, t_caID
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;

		IF NOT t_lintingApplies THEN
			UPDATE ca
				SET LINTING_APPLIES = FALSE
				WHERE ID = t_caID;
		END IF;
	END IF;

	FOR l_cdp IN (
		SELECT x509_crlDistributionPoints(cert_data) URL
	) LOOP
		INSERT INTO crl (
				CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
			)
			VALUES (
				t_issuerCAID, trim(l_cdp.URL), now() AT TIME ZONE 'UTC', TRUE
			)
			ON CONFLICT DO NOTHING;
	END LOOP;

	FOR l_aiaOCSP IN (
		SELECT x509_authorityInfoAccess(cert_data, 1) URL
	) LOOP
		INSERT INTO ocsp_responder (
				CA_ID, URL, NEXT_CHECKS_DUE
			)
			VALUES (
				t_issuerCAID, l_aiaOCSP.URL, now() AT TIME ZONE 'UTC'
			)
			ON CONFLICT DO NOTHING;
	END LOOP;

	FOR l_aiaCAIssuer IN (
		SELECT x509_authorityInfoAccess(cert_data, 2) URL
	) LOOP
		INSERT INTO ca_issuer (
				CA_ID, URL, NEXT_CHECK_DUE, FIRST_CERTIFICATE_ID, IS_ACTIVE
			)
			VALUES (
				t_issuerCAID, l_aiaCAIssuer.URL, now() AT TIME ZONE 'UTC', t_certificateID, TRUE
			)
			ON CONFLICT DO NOTHING;
	END LOOP;

	RETURN t_certificateID;

EXCEPTION
	WHEN others THEN
		RETURN NULL;
END;
$$ LANGUAGE plpgsql;
