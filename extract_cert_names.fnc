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

CREATE OR REPLACE FUNCTION extract_cert_names(
	cert_id					certificate.ID%TYPE,
	issuerca_id				ca.ID%TYPE
) RETURNS void
AS $$
DECLARE
	l_attribute				RECORD;
BEGIN
	DELETE FROM certificate_identity
		WHERE CERTIFICATE_ID = cert_id;

	FOR l_attribute IN (
				SELECT x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'commonName', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'organizationName', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_nameAttributes(c.CERTIFICATE, 'emailAddress', TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'emailAddress', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_altNames(c.CERTIFICATE, 1, TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'rfc822Name', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_altNames(c.CERTIFICATE, 2, TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'dNSName', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_altNames(c.CERTIFICATE, 7, TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'iPAddress', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;

	FOR l_attribute IN (
				SELECT x509_nameAttributes(c.CERTIFICATE, 'organizationalUnitName', TRUE) NAME_VALUE
					FROM certificate c
					WHERE c.ID = cert_id
					ORDER BY NAME_VALUE DESC
			) LOOP
		BEGIN
			INSERT INTO certificate_identity (
					CERTIFICATE_ID, ISSUER_CA_ID, NAME_TYPE, NAME_VALUE
				)
				VALUES (
					cert_id, issuerca_id, 'organizationalUnitName', l_attribute.NAME_VALUE
				);
		EXCEPTION
			WHEN unique_violation THEN
				NULL;
		END;
	END LOOP;
END;
$$ LANGUAGE plpgsql;
