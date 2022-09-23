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

CREATE OR REPLACE FUNCTION ccadb_disclosure_group_summary(
	trustContextID		trust_context.ID%TYPE,
	disclosureStatus	disclosure_status_type,
	anchor				text,
	bgColour			text
) RETURNS text
AS $$
DECLARE
	t_disclosureStatusField	text;
	t_query					text;
	t_summary				text	:= '';
	t_further				text	:= '';
	l_record				RECORD;
BEGIN
	IF trustContextID = 5 THEN
		t_disclosureStatusField := 'MOZILLA_DISCLOSURE_STATUS';
	ELSIF trustContextID = 1 THEN
		t_disclosureStatusField := 'MICROSOFT_DISCLOSURE_STATUS';
	ELSIF trustContextID = 12 THEN
		t_disclosureStatusField := 'APPLE_DISCLOSURE_STATUS';
	END IF;

	t_query :=
'SELECT cc.INCLUDED_CERTIFICATE_OWNER, count(*) NUM_CERTS
	FROM ccadb_certificate cc
	WHERE cc.' || t_disclosureStatusField || ' = ''' || disclosureStatus || '''
		AND cc.CERTIFICATE_ID IS NOT NULL
	GROUP BY cc.INCLUDED_CERTIFICATE_OWNER
	ORDER BY cc.INCLUDED_CERTIFICATE_OWNER';

	IF disclosureStatus = 'DisclosureIncomplete' THEN
		t_further := ' Further';
	END IF;

	FOR l_record IN EXECUTE t_query LOOP
		t_summary := t_summary ||
'  <TR>
    <TD>' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '<I>Unknown</I>') || '</TD>
    <TD>' || l_record.NUM_CERTS::text || '</TD>
  </TR>
';
	END LOOP;

	IF t_summary != '' THEN
		t_summary :=
'<A name="' || anchor || '"><BR></A><TABLE style="background-color:' || bgColour || '">
  <TR>
    <TH>Root Owner</TH>
    <TH># of Certificates Requiring' || t_further || ' Disclosure</TH>
  </TR>
' || t_summary || '
</TABLE>
';
	END IF;

	RETURN t_summary;
END;
$$ LANGUAGE plpgsql;
