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

CREATE OR REPLACE FUNCTION download_cert(
	cert_identifier			text
) RETURNS text
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
BEGIN
	IF length(cert_identifier) = 64 THEN
		SELECT c.CERTIFICATE
			INTO t_certificate
			FROM certificate c
			WHERE digest(c.CERTIFICATE, 'sha256') = decode(cert_identifier, 'hex');
	ELSIF translate(cert_identifier, '0123456789', '') = '' THEN
		SELECT c.CERTIFICATE
			INTO t_certificate
			FROM certificate c
			WHERE c.ID = cert_identifier::bigint;
	END IF;
	IF t_certificate IS NULL THEN
		RETURN NULL;
	END IF;

	RETURN
'[BEGIN_HEADERS]
Content-Disposition: attachment; filename="' || cert_identifier || '.crt"
Content-Type: application/pkix-cert
[END_HEADERS]
' || pem_cert(t_certificate);
END;
$$ LANGUAGE plpgsql;
