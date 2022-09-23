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

CREATE OR REPLACE FUNCTION ccadb_disclosure_group2(
	trustContextID		trust_context.ID%TYPE,
	disclosureStatus	disclosure_status_type,
	anchor				text,
	description			text,
	bgColour			text
) RETURNS text[]
AS $$
DECLARE
	t_disclosureStatusField	text;
	t_opt					text		:= '';
	t_query					text;
	t_earliestSCT			text;
	t_row					text;
	t_server				text		:= '';
	t_serverCount			integer		:= 0;
	t_serverTrustCount		integer		:= 0;
	t_nonServer				text		:= '';
	t_nonServerCount		integer		:= 0;
	t_nonServerTrustCount	integer		:= 0;
	t_group					text;
	t_problems				text[];
	t_spki					bytea;
	l_record				RECORD;
BEGIN
	IF trustContextID = 5 THEN
		t_disclosureStatusField := 'MOZILLA_DISCLOSURE_STATUS';
		t_opt := '&opt=mozilladisclosure';
	ELSIF trustContextID = 1 THEN
		t_disclosureStatusField := 'MICROSOFT_DISCLOSURE_STATUS';
	ELSIF trustContextID = 12 THEN
		t_disclosureStatusField := 'APPLE_DISCLOSURE_STATUS';
	END IF;

	t_query :=
'SELECT *,
		cc.' || 'LAST_' || t_disclosureStatusField || '_CHANGE	LAST_DISCLOSURE_STATUS_CHANGE
	FROM ccadb_certificate cc
	WHERE cc.' || t_disclosureStatusField || ' = ''' || disclosureStatus || '''
		AND cc.CERTIFICATE_ID IS NOT NULL
	ORDER BY cc.INCLUDED_CERTIFICATE_OWNER, cc.ISSUER_O, cc.ISSUER_CN NULLS FIRST, cc.CERT_RECORD_TYPE DESC,
			cc.SUBJECT_O, cc.SUBJECT_CN NULLS FIRST, cc.CERT_NAME NULLS FIRST, cc.CERT_SHA256';

	FOR l_record IN EXECUTE t_query LOOP
		SELECT to_char(min(ctle.ENTRY_TIMESTAMP), 'YYYY-MM-DD')
					|| '&nbsp; <FONT class="small">'
					|| to_char(min(ctle.ENTRY_TIMESTAMP), 'HH24:MI:SS UTC')
			INTO t_earliestSCT
			FROM ct_log_entry ctle
			WHERE ctle.CERTIFICATE_ID = l_record.CERTIFICATE_ID;

		t_row :=
'  <TR>
    <TD>';

		SELECT count(*)
			INTO t_serverTrustCount
			FROM certificate c
			WHERE c.ID = l_record.CERTIFICATE_ID
				AND (
					x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
					OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
					OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
				)
				AND EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND ctp.TRUST_PURPOSE_ID = 1
							AND ctp.IS_TIME_VALID
							AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
				);
		IF t_serverTrustCount > 0 THEN
			t_serverCount := t_serverCount + 1;
			t_row := t_row || t_serverCount::text || '</TD>
    <TD>' || coalesce(t_earliestSCT, '') || '</TD>
    <TD>' || coalesce(to_char(l_record.LAST_DISCLOSURE_STATUS_CHANGE, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">' || to_char(l_record.LAST_DISCLOSURE_STATUS_CHANGE, 'HH24:MI:SS UTC'), '') || '</TD>
    <TD>Server';
		ELSE
			t_nonServerCount := t_nonServerCount + 1;
			t_row := t_row || t_nonServerCount::text || '</TD>
    <TD>' || coalesce(t_earliestSCT, '') || '</TD>
    <TD>' || coalesce(to_char(l_record.LAST_DISCLOSURE_STATUS_CHANGE, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">' || to_char(l_record.LAST_DISCLOSURE_STATUS_CHANGE, 'HH24:MI:SS UTC'), '') || '</TD>
    <TD>';
		END IF;

		SELECT count(*)
			INTO t_nonServerTrustCount
			FROM certificate c
			WHERE c.ID = l_record.CERTIFICATE_ID
				AND x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.4')
				AND EXISTS (
					SELECT 1
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = c.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND ctp.TRUST_PURPOSE_ID = 3
							AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
				);
		IF t_nonServerTrustCount > 0 THEN
			t_row := t_row || ' Email';
		END IF;

		t_row := t_row || '</TD>
    <TD>';

		IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
			t_row := t_row || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
		ELSE
			t_row := t_row || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
		END IF;
		t_row := t_row || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
		IF l_record.CERT_RECORD_TYPE = 'Root Certificate' THEN
			t_row := t_row || '<B>[Root]</B> ';
		END IF;
		IF l_record.CCADB_RECORD_ID IS NOT NULL THEN
			t_row := t_row || '<A href="//ccadb.force.com/' || l_record.CCADB_RECORD_ID || '" target="_blank">';
		END IF;
		t_row := t_row || coalesce(html_escape(l_record.CERT_NAME), '&nbsp;');
		IF l_record.CCADB_RECORD_ID IS NOT NULL THEN
			t_row := t_row || '</A>';
		END IF;
		t_row := t_row || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || t_opt || '" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		t_problems := disclosure_problems(l_record.CERTIFICATE_ID, trustContextID);
		IF array_length(t_problems, 1) > 0 THEN
			SELECT digest(x509_publicKey(c.CERTIFICATE), 'sha256')
				INTO t_spki
				FROM certificate c
				WHERE c.ID = l_record.CERTIFICATE_ID;
			t_row := t_row ||
'  <TR>
    <TD colspan="10" style="font-family:monospace;font-size:8pt;color:black;padding-left:20px">
';
			IF disclosureStatus != 'DisclosureIncomplete' THEN
				t_row := t_row ||
'      <A href="//ccadb.force.com/s/global-search/' || encode(t_spki, 'hex') || '" target="_blank">Review this Subject CA''s CCADB records</A><BR>
';
			END IF;
			t_row := t_row || array_to_string(t_problems, '<BR>') || '
    </TD>
  </TR>
';
		END IF;

		IF t_serverTrustCount > 0 THEN
			t_server := t_server || t_row;
		ELSE
			t_nonServer := t_nonServer || t_row;
		END IF;
	END LOOP;
	t_group :=
'<BR><BR><SPAN class="title" style="color:#041C2C;background-color:' || bgColour || '"><A name="' || anchor || '">' || description || '</A></SPAN>
<SPAN class="whiteongrey">' || t_serverCount::text || ' Server + ' || t_nonServerCount::text || ' Non-Server CA certificates</SPAN>
<BR>
<TABLE style="background-color:' || bgColour || '">
  <TR>
    <TH>#</TH>
    <TH>Earliest SCT</TH>
    <TH>Listed Here Since</TH>
    <TH>Trusted For Server? Email?</TH>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_server;
	IF (t_serverCount + t_nonServerCount) = 0 THEN
		t_group := t_group ||
'  <TR><TD colspan="10">None found</TD></TR>
';
	ELSIF t_nonServerCount > 0 THEN
		t_nonServer :=
'  <TR><TD colspan="10" style="background-color:#FFFFFF">&nbsp;</TD></TR>
' || t_nonServer;
	END IF;
	t_group := t_group || t_nonServer ||
'</TABLE>
';

	RETURN ARRAY[t_group, t_serverCount::text, t_nonServerCount::text];
END;
$$ LANGUAGE plpgsql;
