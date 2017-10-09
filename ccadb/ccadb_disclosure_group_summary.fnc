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
