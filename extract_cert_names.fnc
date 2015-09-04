/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015 COMODO CA Limited
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
BEGIN
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'commonName',
				x509_nameAttributes(c.CERTIFICATE, 'commonName', TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'organizationName',
				x509_nameAttributes(c.CERTIFICATE, 'organizationName', TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'emailAddress',
				x509_nameAttributes(c.CERTIFICATE, 'emailAddress', TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'rfc822Name',
				x509_altNames(c.CERTIFICATE, 1, TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'dNSName',
				x509_altNames(c.CERTIFICATE, 2, TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'iPAddress',
				x509_altNames(c.CERTIFICATE, 7, TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;
	INSERT INTO certificate_identity (
			CERTIFICATE_ID, NAME_TYPE,
			NAME_VALUE,
			ISSUER_CA_ID
		)
		SELECT cert_id, 'organizationalUnitName',
				x509_nameAttributes(c.CERTIFICATE, 'organizationalUnitName', TRUE),
				issuerca_id
			FROM certificate c
			WHERE c.ID = cert_id;

EXCEPTION
	WHEN unique_violation THEN
		UPDATE certificate_identity
			SET ISSUER_CA_ID = issuerca_id
			WHERE CERTIFICATE_ID = cert_id;
END;
$$ LANGUAGE plpgsql;
