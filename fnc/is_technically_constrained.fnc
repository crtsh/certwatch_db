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

CREATE OR REPLACE FUNCTION is_technically_constrained(
	cert_data				bytea
) RETURNS boolean
AS $$
DECLARE
	t_extKeyUsages		text[];
	t_constrainedServer	boolean		:= FALSE;
	t_constrainedEmail	boolean		:= FALSE;
	t_text				text;
	t_temp				text;
	t_offset1			integer;
	t_index				integer		:= 2;
	t_line				text[];
	t_isPermitted		boolean;
	t_permittedDNS		boolean		:= FALSE;
	t_permittedIP		boolean		:= FALSE;
	t_permittedDirName	boolean		:= FALSE;
	t_permittedEmail	boolean		:= FALSE;
	t_excludedAllDNS	boolean		:= FALSE;
	t_excludedAllIPv4	boolean		:= FALSE;
	t_excludedAllIPv6	boolean		:= FALSE;
BEGIN
	SELECT array_agg(x509_extkeyusages)
		INTO t_extKeyUsages
		FROM x509_extkeyusages(cert_data);

	-- "For a certificate to be considered technically constrained, the certificate MUST include an Extended Key Usage (EKU) extension"
	-- "The anyExtendedKeyUsage KeyPurposeId MUST NOT appear within this extension"
	IF (t_extKeyUsages IS NULL) OR (t_extKeyUsages @> ARRAY['2.5.29.37.0']) THEN
		RETURN FALSE;
	END IF;

	IF (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.1'])							-- id-kp-serverAuth.
			OR (
				(t_extKeyUsages @> ARRAY['2.16.840.1.113730.4.1'])				-- id-Netscape-stepUp.
				AND (x509_notBefore(cert_data) < '2016-08-23'::date)
			) THEN
		IF (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.3'])						-- id-kp-codeSigning.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.4'])				-- id-kp-emailProtection.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.8'])				-- id-kp-timeStamping.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.9'])				-- id-kp-OCSPSigning.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.4.1.11129.2.4.4']) THEN	-- Precertificate Signing Certificate.
			-- MUST NOTs from TLSBR 7.1.2.10.6.
			RETURN FALSE;
		END IF;
		t_constrainedServer := TRUE;
	ELSIF t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.4'] THEN						-- id-kp-emailProtection.
		IF (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.1'])						-- id-kp-serverAuth.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.3'])				-- id-kp-codeSigning.
				OR (t_extKeyUsages @> ARRAY['1.3.6.1.5.5.7.3.8']) THEN			-- id-kp-timeStamping.
			-- SBR 7.1.2.2(g): "id-kp-serverAuth, id-kp-codeSigning, id-kp-timeStamping...SHALL NOT be present."
			RETURN FALSE;
		END IF;
		t_constrainedEmail := TRUE;
	ELSE
		RETURN TRUE;	-- Constrained (not Server or Email).
	END IF;

	t_text := x509_print(cert_data);
	t_temp := '            X509v3 Name Constraints:';
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
			ELSIF trim(t_line[t_index]) LIKE 'email:%' THEN
				t_permittedEmail := TRUE;
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

	IF NOT t_permittedDirName THEN
		RETURN FALSE;
	ELSIF t_constrainedServer THEN
		IF NOT (t_permittedDNS OR t_excludedAllDNS) THEN
			RETURN FALSE;
		ELSIF NOT (t_permittedIP OR (t_excludedAllIPv4 AND t_excludedAllIPv6)) THEN
			RETURN FALSE;
		END IF;
	ELSIF t_constrainedEmail THEN
		IF NOT t_permittedEmail THEN
			RETURN FALSE;
		END IF;
	END IF;

	RETURN TRUE;	-- Constrained (Server or Email).
END;
$$ LANGUAGE plpgsql;
