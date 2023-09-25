/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2023 Sectigo Limited
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

CREATE OR REPLACE FUNCTION import_any_cert(
	_cert_data				IN		bytea,
	_issuer_ca_id			IN		certificate.ISSUER_CA_ID%TYPE,
	_subject_ca_id				OUT	ca.ID%TYPE,
	_certificate_id				OUT	certificate.ID%TYPE
) AS $$
DECLARE
	t_name				ca.NAME%TYPE;
	t_publicKey			ca.PUBLIC_KEY%TYPE;
	t_isNewCA			boolean							:= FALSE;
BEGIN
	IF _cert_data IS NULL THEN
		RETURN;
	END IF;

	-- What (if any) records already exist for this certificate?
	-- Optimization: Compare x509_notAfter() to avoid wasting time checking the wrong "certificate" partitions.
	SELECT c.ID, cac.CA_ID
		INTO _certificate_id, _subject_ca_id
		FROM certificate c
				LEFT OUTER JOIN ca_certificate cac ON (
					c.ID = cac.CERTIFICATE_ID
				)
		WHERE digest(_cert_data, 'sha256') = digest(c.CERTIFICATE, 'sha256')
			AND coalesce(x509_notAfter(_cert_data), 'infinity'::timestamp) = coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp);
	IF _subject_ca_id IS NOT NULL THEN
		RETURN;	-- "certificate", "ca_certificate", and subject "ca" records already exist, so there's nothing more to do.
	END IF;

	-- If this is a CA certificate, find or create the subject "ca" record.  This needs to be done before we look for the issuer "ca" record, because the certificate might be self-signed.
	IF x509_canIssueCerts(_cert_data) THEN
		t_name := x509_subjectName(_cert_data);
		t_publicKey := coalesce(x509_publicKey(_cert_data), E'\\x00');

		SELECT ca.ID
			INTO _subject_ca_id
			FROM ca
			WHERE ca.NAME = t_name
				AND ca.PUBLIC_KEY = t_publicKey;
		IF _subject_ca_id IS NULL THEN
			INSERT INTO ca ( NAME, PUBLIC_KEY )
				VALUES ( t_name, t_publicKey )
				RETURNING ca.ID
					INTO _subject_ca_id;
			t_isNewCA := TRUE;
		END IF;
	END IF;

	-- Find the issuer "ca" ID (if not already known).
	IF _issuer_ca_id IS NULL THEN
		_issuer_ca_id := find_issuer(_cert_data);
	END IF;

	-- The applicability of linting flows down from the issuer.
	IF t_isNewCA AND (_issuer_ca_id != -1) THEN		-- -1 = Issuer not found.
		UPDATE ca
			SET LINTING_APPLIES = (
				SELECT ca_issuer.LINTING_APPLIES
					FROM ca ca_issuer
					WHERE ca_issuer.ID = _issuer_ca_id
			)
			WHERE ca.ID = _subject_ca_id;
	END IF;

	-- Create the "certificate" record.
	IF _certificate_id IS NULL THEN
		INSERT INTO certificate ( CERTIFICATE, ISSUER_CA_ID )
			VALUES ( _cert_data, _issuer_ca_id )
			RETURNING ID
				INTO _certificate_id;
	END IF;

	-- If applicable, create the "ca_certificate" record.
	IF _subject_ca_id IS NOT NULL THEN
		INSERT INTO ca_certificate ( CERTIFICATE_ID, CA_ID )
			VALUES ( _certificate_id, _subject_ca_id );
	END IF;
END;
$$ LANGUAGE plpgsql;
