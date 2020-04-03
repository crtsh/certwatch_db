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

CREATE OR REPLACE FUNCTION lint_tbscertificate(
	tbscert					bytea
) RETURNS text
AS $$
DECLARE
	t_certificate			bytea;
	t_header				text;
	t_certType				integer;
	t_output				text := '';
	l_linter				RECORD;
BEGIN
	-- Add ASN.1 packaging and a dummy signature to create a valid X.509
	-- certificate that the linters will parse.
	t_certificate := tbscert || E'\\x3003060100030100';
	t_header := to_hex(length(t_certificate));
	IF length(t_header) % 2 > 0 THEN
		t_header := '0' || t_header;
	END IF;
	IF length(t_header) > 2 THEN
		t_header := to_hex(128 + (length(t_header) / 2)) || t_header;
	END IF;
	t_certificate := E'\\x30' || decode(t_header, 'hex') || t_certificate;

	RETURN lint_certificate(t_certificate, TRUE);
END;
$$ LANGUAGE plpgsql STRICT;
