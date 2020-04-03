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
	l_identity				RECORD;
BEGIN
	FOR l_identity IN (
		SELECT sub.VALUE,
				CASE WHEN sub.TYPE IN ('2.5.4.3', 'type2') THEN substring(sub.VALUE FROM position('.' IN (sub.VALUE || '.')) + 1)		-- commonName, dNSName.
					WHEN sub.TYPE IN ('1.2.840.113549.1.9.1', 'type1') THEN substring(sub.VALUE FROM position('@' IN sub.VALUE) + 1)	-- emailAddress, rfc822Name.
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
			GROUP BY sub.VALUE, DOMAIN_NAME
	) LOOP
		t_string := t_string || ' ' || l_identity.VALUE;
		IF coalesce(l_identity.DOMAIN_NAME, '') != '' THEN
			LOOP
				t_string := t_string || ' ' || l_identity.DOMAIN_NAME;
				t_position := coalesce(position('.' IN l_identity.DOMAIN_NAME), 0);
				EXIT WHEN t_position = 0;
				l_identity.DOMAIN_NAME := substring(l_identity.DOMAIN_NAME FROM (t_position + 1));
			END LOOP;
		END IF;
	END LOOP;

	RETURN strip(to_tsvector(ltrim(t_string)));
END;
$$ LANGUAGE plpgsql STRICT IMMUTABLE;
