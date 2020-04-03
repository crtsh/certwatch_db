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

CREATE OR REPLACE FUNCTION get_ca_name_attribute(
	ca_id_					ca.ID%TYPE,
	attribute_type			text		= '_friendlyName_'
) RETURNS text
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_primaryName		text;
BEGIN
	SELECT c.CERTIFICATE
		INTO t_certificate
		FROM ca_certificate cac, certificate c
		WHERE cac.CA_ID = ca_id_
			AND cac.CERTIFICATE_ID = c.ID
		LIMIT 1;

	IF attribute_type = '_friendlyName_' THEN
		SELECT x509_nameattributes
			INTO t_primaryName
			FROM x509_nameAttributes(t_certificate, 'commonName', TRUE)
			ORDER BY row_number() OVER() DESC
			LIMIT 1;
		IF t_primaryName IS NULL THEN
			SELECT x509_nameattributes
				INTO t_primaryName
				FROM x509_nameAttributes(t_certificate, 'organizationalUnitName', TRUE)
				ORDER BY row_number() OVER() DESC
				LIMIT 1;
			IF t_primaryName IS NULL THEN
				t_primaryName := x509_nameAttributes(
					t_certificate, 'organizationName', TRUE
				) LIMIT 1;
			END IF;
		END IF;
	ELSE
		SELECT x509_nameattributes
			INTO t_primaryName
			FROM x509_nameAttributes(t_certificate, attribute_type, TRUE)
			ORDER BY row_number() OVER() DESC
			LIMIT 1;
	END IF;

	RETURN t_primaryName;
END;
$$ LANGUAGE plpgsql STRICT;
