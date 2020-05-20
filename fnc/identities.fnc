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

CREATE OR REPLACE FUNCTION identities(
	cert					bytea,
	is_subject				boolean		DEFAULT true
) RETURNS tsvector
AS $$
DECLARE
	t_string				text := '';
	t_position				integer;
	t_doReverse				boolean;
	l_identity				RECORD;
BEGIN
	FOR l_identity IN (
		SELECT lower(sub.VALUE) AS IDENTITY,
				CASE WHEN sub.TYPE IN ('2.5.4.3', 'type2') THEN lower(sub.VALUE)															-- commonName, dNSName.
					WHEN sub.TYPE IN ('1.2.840.113549.1.9.1', 'type1') THEN lower(substring(sub.VALUE FROM position('@' IN sub.VALUE) + 1))	-- emailAddress, rfc822Name.
				END AS DOMAIN_NAME
			FROM (
				SELECT encode(RAW_VALUE, 'escape') AS VALUE,
						ATTRIBUTE_OID AS TYPE
					FROM public.x509_nameAttributes_raw(cert, is_subject)
				UNION
				SELECT encode(RAW_VALUE, 'escape') AS VALUE,
						('type' || TYPE_NUM::text) AS TYPE
					FROM public.x509_altNames_raw(cert, is_subject)
			) sub
			GROUP BY IDENTITY, DOMAIN_NAME
			ORDER BY LENGTH(lower(sub.VALUE)) DESC
	) LOOP
		t_string := t_string || ' ' || l_identity.IDENTITY;
		IF coalesce(l_identity.DOMAIN_NAME, '') = '' THEN
			t_string := t_string || ' ' || reverse(l_identity.IDENTITY);
		ELSE
			IF l_identity.DOMAIN_NAME != l_identity.IDENTITY THEN
				t_string := t_string || ' ' || l_identity.DOMAIN_NAME || ' ' || reverse(l_identity.IDENTITY);
			END IF;

			t_doReverse := TRUE;
			LOOP
				t_position := coalesce(position('.' IN l_identity.DOMAIN_NAME), 0);
				EXIT WHEN t_position = 0;
				l_identity.DOMAIN_NAME := substring(l_identity.DOMAIN_NAME FROM (t_position + 1));
				t_string := t_string || ' ' || l_identity.DOMAIN_NAME;
				IF t_doReverse THEN
					IF position((reverse(l_identity.DOMAIN_NAME) || '.') in t_string) = 0 THEN
						t_string := t_string || ' ' || reverse(l_identity.DOMAIN_NAME);
					END IF;
					t_doReverse := FALSE;
				END IF;
			END LOOP;
		END IF;
	END LOOP;

	RETURN strip(to_tsvector('public.certwatch', ltrim(t_string)));
END;
$$ LANGUAGE plpgsql STRICT IMMUTABLE;
