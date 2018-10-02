CREATE OR REPLACE FUNCTION ccadb_disclosure_group(
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
	t_table					text		:= '';
	t_group					text;
	t_count					bigint		:= 0;
	l_record				RECORD;
BEGIN
	IF trustContextID = 5 THEN
		t_disclosureStatusField := 'MOZILLA_DISCLOSURE_STATUS';
		t_opt := '&opt=mozilladisclosure';
	ELSIF trustContextID = 1 THEN
		t_disclosureStatusField := 'MICROSOFT_DISCLOSURE_STATUS';
	END IF;

	IF disclosureStatus IS NULL THEN
		t_query :=
'SELECT cc.CERT_NAME, cc.INCLUDED_CERTIFICATE_ID, cc.INCLUDED_CERTIFICATE_OWNER, cc.CERT_RECORD_TYPE,
		cc.ISSUER_O, cc.ISSUER_CN, cc.SUBJECT_O, cc.SUBJECT_CN, cc.CERT_SHA256, cc.CCADB_RECORD_ID,
		ic.CERTIFICATE_ID, ic.PROBLEMS
	FROM ccadb_certificate cc
			LEFT OUTER JOIN invalid_certificate ic
				ON (cc.CERT_SHA256 = digest(ic.CERTIFICATE_AS_LOGGED, ''sha256''))
	WHERE cc.CERTIFICATE_ID IS NULL
	ORDER BY (ic.PROBLEMS IS NOT NULL), cc.INCLUDED_CERTIFICATE_OWNER,
			cc.ISSUER_O, cc.ISSUER_CN NULLS FIRST, cc.CERT_RECORD_TYPE DESC,
			cc.SUBJECT_O, cc.SUBJECT_CN NULLS FIRST, cc.CERT_NAME NULLS FIRST, cc.CERT_SHA256';
	ELSE
		t_query :=
'SELECT *
	FROM ccadb_certificate cc
	WHERE cc.' || t_disclosureStatusField || ' = ''' || disclosureStatus || '''
		AND cc.CERTIFICATE_ID IS NOT NULL
	ORDER BY cc.INCLUDED_CERTIFICATE_OWNER, cc.ISSUER_O, cc.ISSUER_CN NULLS FIRST, cc.CERT_RECORD_TYPE DESC,
			cc.SUBJECT_O, cc.SUBJECT_CN NULLS FIRST, cc.CERT_NAME NULLS FIRST';
	END IF;

	FOR l_record IN EXECUTE t_query LOOP
		t_count := t_count + 1;
		t_table := t_table ||
'  <TR>
    <TD>';
		IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
			t_table := t_table || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
		ELSE
			t_table := t_table || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
		END IF;
		t_table := t_table || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
		IF l_record.CERT_RECORD_TYPE = 'Root Certificate' THEN
			t_table := t_table || '<B>[Root]</B> ';
		END IF;
		IF l_record.CCADB_RECORD_ID IS NOT NULL THEN
			t_table := t_table || '<A href="//ccadb.force.com/' || l_record.CCADB_RECORD_ID || '" target="_blank">';
		END IF;
		t_table := t_table || coalesce(html_escape(l_record.CERT_NAME), '&nbsp;');
		IF l_record.CCADB_RECORD_ID IS NOT NULL THEN
			t_table := t_table || '</A>';
		END IF;
		IF disclosureStatus IS NOT NULL THEN
			t_table := t_table || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || t_opt || '" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		ELSE
			t_table := t_table || '</TD>
    <TD style="font-family:monospace">' || upper(encode(l_record.CERT_SHA256, 'hex')) || '</TD>
    <TD>' || coalesce(html_escape(l_record.PROBLEMS), '&nbsp;');
			IF l_record.CERTIFICATE_ID IS NOT NULL THEN
				t_table := t_table || '.<BR><A href="/?id=' || l_record.CERTIFICATE_ID::text || '">View the correct encoding of this certificate</A>';
			END IF;
			t_table := t_table || '</TD>
  </TR>
';
		END IF;
	END LOOP;

	t_group :=
'<BR><BR><SPAN class="title" style="background-color:' || bgColour || '"><A name="' || anchor || '">' || description || '</A></SPAN>
<SPAN class="whiteongrey">' || t_count::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:' || bgColour || '">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
';
	IF disclosureStatus IS NULL THEN
		t_group := t_group ||
'    <TH>Encoding Problems?</TH>
';
	END IF;
	t_group := t_group ||
'  </TR>
' || t_table;
	IF t_count = 0 THEN
		t_group := t_group ||
'  <TR><TD colspan="6">None found</TD></TR>
';
	END IF;
	t_group := t_group ||
'</TABLE>
';

	RETURN ARRAY[t_group, t_count::text];
END;
$$ LANGUAGE plpgsql;
