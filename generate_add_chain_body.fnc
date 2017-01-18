/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2017 COMODO CA Limited
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

CREATE OR REPLACE FUNCTION generate_add_chain_body(
	cert_data				certificate.CERTIFICATE%TYPE
) RETURNS text
AS $$
DECLARE
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_certChain			integer[];
	t_output			text;
	t_hexCertificate	text;
	l_ca				RECORD;
	l_caCert			RECORD;
BEGIN
	FOR l_ca IN (
				SELECT *
					FROM ca
					WHERE ca.NAME = x509_issuerName(cert_data)
						AND ca.PUBLIC_KEY != E'\\x00'
					ORDER BY octet_length(PUBLIC_KEY) DESC
			) LOOP
		IF x509_verify(cert_data, l_ca.PUBLIC_KEY) THEN
			t_issuerCAID := l_ca.ID;
			EXIT;
		END IF;
	END LOOP;
	IF t_issuerCAID IS NULL THEN
		RETURN NULL;
	END IF;

	FOR l_caCert IN (
				SELECT cac.CERTIFICATE_ID
					FROM ca_certificate cac
					WHERE cac.CA_ID = t_issuerCAID
					ORDER BY cac.CERTIFICATE_ID
					LIMIT 1
			) LOOP
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, TRUE, 5, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, TRUE, 1, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, TRUE, 12, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, FALSE, 5, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, FALSE, 1, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
		SELECT enumerate_chains(l_caCert.CERTIFICATE_ID, FALSE, 12, NULL)
			INTO t_certChain;
		EXIT WHEN FOUND;
	END LOOP;

	IF (t_certChain IS NULL) OR (array_length(t_certChain, 1) = 0) THEN
		RETURN NULL;
	END IF;

	t_output := '{"chain":["' || replace(encode(cert_data, 'base64'), chr(10), '') || '"';

	FOR l_certNo IN 1..array_length(t_certChain, 1) LOOP
		SELECT replace(encode(c.CERTIFICATE, 'base64'), chr(10), '')
			INTO t_hexCertificate
			FROM certificate c
			WHERE c.ID = t_certChain[l_certNo];
		t_output := t_output || ',"' || t_hexCertificate || '"';
	END LOOP;

	RETURN t_output || ']}';
END;
$$ LANGUAGE plpgsql;
