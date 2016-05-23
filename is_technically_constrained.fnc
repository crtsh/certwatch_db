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

CREATE OR REPLACE FUNCTION is_technically_constrained(
	cert_data				bytea
) RETURNS boolean
AS $$
DECLARE
	t_count				integer;
	t_serverAuth		boolean;
	t_codeSigning		boolean;
	t_text				text;
	t_temp				text;
	t_offset1			integer;
	t_index				integer		:= 1;
	t_line				text[];
	t_isPermitted		boolean;
	t_permittedDNS		boolean		:= FALSE;
	t_permittedIP		boolean		:= FALSE;
	t_permittedDirName	boolean		:= FALSE;
	t_excludedAllDNS	boolean		:= FALSE;
	t_excludedAllIPv4	boolean		:= FALSE;
	t_excludedAllIPv6	boolean		:= FALSE;
BEGIN
	-- "For a certificate to be considered technically constrained, the certificate MUST include an Extended Key Usage (EKU) extension"
	SELECT count(*)
		INTO t_count
		FROM x509_extkeyusages(cert_data);
	IF t_count = 0 THEN
		RETURN FALSE;
	END IF;

	-- "The anyExtendedKeyUsage KeyPurposeId MUST NOT appear within this extension"
	SELECT count(*)
		INTO t_count
		FROM x509_extkeyusages(cert_data)
		WHERE x509_extkeyusages = '2.5.29.37.0';
	IF t_count > 0 THEN
		RETURN FALSE;
	END IF;

	t_serverAuth := x509_isEKUPermitted(cert_data, '1.3.6.1.5.5.7.3.1')
					OR x509_isEKUPermitted(cert_data, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
					OR x509_isEKUPermitted(cert_data, '2.16.840.1.113730.4.1');	-- NS Step-Up.
	-- Don't consider Code Signing, because this is no longer of interest to Mozilla.
	t_codeSigning := FALSE;	-- x509_isEKUPermitted(cert_data, '1.3.6.1.5.5.7.3.3');
	IF t_serverAuth OR t_codeSigning THEN
		t_text := x509_print(cert_data);
		t_temp := '            X509v3 Name Constraints: ' || chr(10);
		t_offset1 := position(t_temp in t_text);
		IF t_offset1 = 0 THEN
			RETURN FALSE;
		END IF;

		t_line := regexp_split_to_array(substring(t_text from (t_offset1 + length(t_temp))), E'\\n+');
		LOOP
			IF t_line[t_index] = '                Permitted:' THEN
				t_isPermitted := TRUE;
			ELSIF t_line[t_index] = '                Excluded:' THEN
				t_isPermitted := FALSE;
			ELSE
				EXIT WHEN (t_line[t_index] IS NULL) OR (t_line[t_index] NOT LIKE '                  %');
			END IF;
			EXIT WHEN t_isPermitted IS NULL;

			IF t_isPermitted THEN
				IF trim(t_line[t_index]) LIKE 'DNS:%' THEN
					t_permittedDNS := TRUE;
				ELSIF trim(t_line[t_index]) LIKE 'IP:%' THEN
					t_permittedIP := TRUE;
				ELSIF trim(t_line[t_index]) LIKE 'DirName:%' THEN
					t_permittedDirName := TRUE;
				END IF;
			ELSE
				IF trim(t_line[t_index]) = 'DNS:' THEN
					t_excludedAllDNS := TRUE;
				ELSIF trim(t_line[t_index]) = 'IP:0.0.0.0/0.0.0.0' THEN
					t_excludedAllIPv4 := TRUE;
				ELSIF trim(t_line[t_index]) = 'IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0' THEN
					t_excludedAllIPv6 := TRUE;
				END IF;
			END IF;

			t_index := t_index + 1;
		END LOOP;

		IF t_serverAuth THEN
			IF NOT (t_permittedDNS OR t_excludedAllDNS) THEN
				RETURN FALSE;
			ELSIF NOT (t_permittedIP OR (t_excludedAllIPv4 AND t_excludedAllIPv6)) THEN
				RETURN FALSE;
			END IF;
		END IF;
		IF t_codeSigning THEN
			IF NOT t_permittedDirName THEN
				RETURN FALSE;
			END IF;
		END IF;
	END IF;

	RETURN TRUE;
END;
$$ LANGUAGE plpgsql;
