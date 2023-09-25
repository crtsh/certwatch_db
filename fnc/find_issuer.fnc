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

CREATE OR REPLACE FUNCTION find_issuer(
	_cert_data				IN		certificate.CERTIFICATE%TYPE
) RETURNS ca.ID%TYPE
AS $$
DECLARE
	l_ca				RECORD;
BEGIN
	FOR l_ca IN (
		SELECT ca.ID, ca.PUBLIC_KEY
			FROM ca
			WHERE ca.NAME = x509_issuerName(_cert_data)
				AND ca.PUBLIC_KEY != E'\\x00'
			ORDER BY octet_length(ca.PUBLIC_KEY) DESC, ca.ID DESC
	) LOOP
		IF x509_verify(_cert_data, l_ca.PUBLIC_KEY) THEN
			RETURN l_ca.ID;
		END IF;
	END LOOP;

	RETURN -1;	-- Issuer not found.
END;
$$ LANGUAGE plpgsql;
