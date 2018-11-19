CREATE OR REPLACE FUNCTION test_websites(
	dir						text,
	sort					integer,
	trustedBy				text
) RETURNS text
AS $$
DECLARE
	t_dirSymbol				text;
	t_oppositeDirection		text;
	t_orderBy				text;
	t_query					text;
	t_params				text	:= '';
	t_paramsWithSort		text	:= '';
	t_baseParams			text	:= '';
	t_output				text;
	t_temp					text;
	t_ocspResponse			text;
	t_count					integer;
	t_certificate			certificate.CERTIFICATE%TYPE;
	t_issuerCertificate		certificate.CERTIFICATE%TYPE;
	l_root					RECORD;
	l_record				RECORD;
BEGIN
	IF dir NOT IN ('^', 'v') THEN
		dir := 'v';
	ELSE
		t_baseParams := t_baseParams || '&dir=' || dir;
	END IF;

	IF dir = 'v' THEN
		t_dirSymbol := '&#8681;';
		t_orderBy := ' ASC';
		t_oppositeDirection := '^';
	ELSE
		t_dirSymbol := '&#8679;';
		t_orderBy := ' DESC';
		t_oppositeDirection := 'v';
	END IF;

	IF coalesce(trustedBy, '') != '' THEN
		t_params := t_params || '&trustedBy=' || trustedBy;
	ELSE
		trustedBy := NULL;
	END IF;

	t_query :=
'SELECT cc.CA_OWNER, cc.CERT_NAME, cc.CERTIFICATE_ID,
		cc.TEST_WEBSITE_VALID, cc.TEST_WEBSITE_VALID_STATUS, cc.TEST_WEBSITE_VALID_CERTIFICATE_ID,
		cc.TEST_WEBSITE_EXPIRED, cc.TEST_WEBSITE_EXPIRED_STATUS, cc.TEST_WEBSITE_EXPIRED_CERTIFICATE_ID,
		cc.TEST_WEBSITE_REVOKED, cc.TEST_WEBSITE_REVOKED_STATUS, cc.TEST_WEBSITE_REVOKED_CERTIFICATE_ID
	FROM ccadb_certificate cc
	WHERE cc.CERT_RECORD_TYPE = ''Root Certificate''
		AND EXISTS (
			SELECT 1
				FROM root_trust_purpose rtp, trust_context tc
				WHERE cc.CERTIFICATE_ID = rtp.CERTIFICATE_ID
					AND rtp.TRUST_PURPOSE_ID = 1	-- Server Authentication.
					AND rtp.TRUST_CONTEXT_ID = tc.ID
					AND tc.CTX = ' || coalesce(quote_literal(trustedBy), 'tc.CTX') || '
		)
	ORDER BY ' || CASE sort
					WHEN 1 THEN 'cc.CA_OWNER' || t_orderBy || ', cc.CERT_NAME' || t_orderBy
					WHEN 2 THEN 'cc.CERT_NAME' || t_orderBy || ', cc.CA_OWNER' || t_orderBy
				END;

	t_output :=
'  <SPAN class="whiteongrey">Test Websites</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH class="outer">Trusted by</TH>
    <TD class="outer">
      <FORM>
      <SELECT name="trustedBy">
';
	FOR l_record IN (
				SELECT ''		AS VALUE,
						'ANY'	AS CTX,
						-2		AS DISPLAY_ORDER
				UNION
				SELECT NULL		AS VALUE,
						'--------------',
						-1		AS DISPLAY_ORDER
				UNION
				SELECT tc.CTX	AS VALUE,
						tc.CTX,
						tc.DISPLAY_ORDER
					FROM trust_context tc
				ORDER BY DISPLAY_ORDER
			) LOOP
		t_output := t_output ||
'        <OPTION value="' || coalesce(l_record.VALUE, '') || '"';
		IF trustedBy = l_record.VALUE THEN
			t_output := t_output || ' selected';
		END IF;
		t_output := t_output || '>' || l_record.CTX || '</OPTION>
';
	END LOOP;
	t_output := t_output || 
'      </SELECT> for Server Authentication
    </TD>
  </TR>
  <TR>
    <TD>&nbsp;</TD>
    <TD class="outer"><INPUT type="submit" class="button" style="font-size:9pt" value="Update"></TD>
  </TR>
</FORM>
</TABLE>
<BR>
<TABLE class="lint">
  <TR>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=1' || t_params || '">CA Owner</A>';
	IF sort = 1 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=2' || t_params || '">Root Certificate</A>';
	IF sort = 2 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH>Valid</TH>
    <TH>Expired</TH>
    <TH>Revoked</TH>
  </TR>
';

	FOR l_root IN EXECUTE t_query LOOP
		t_temp :=
'  <TR>
    <TD>' || l_root.CA_OWNER || '</TD>
    <TD><A href="/?id=' || l_root.CERTIFICATE_ID::text || '" target="_blank">' || l_root.CERT_NAME || '</A></TD>
    <TD>';
		IF (l_root.TEST_WEBSITE_VALID IS NULL) OR (l_root.TEST_WEBSITE_VALID_STATUS IS NULL) THEN
			t_temp := t_temp || '&nbsp;';
		ELSIF l_root.TEST_WEBSITE_VALID_STATUS = 'Not checked' THEN
			t_temp := t_temp || '<FONT color="#888888">No URL available</FONT>';
		ELSE
			IF l_root.TEST_WEBSITE_VALID_STATUS = 'OK' THEN
				SELECT count(*)
					INTO t_count
					FROM certificate c, crl_revoked cr
					WHERE c.ID = l_root.TEST_WEBSITE_VALID_CERTIFICATE_ID
						AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
						AND c.ISSUER_CA_ID = cr.CA_ID;
				IF t_count > 0 THEN
					l_root.TEST_WEBSITE_VALID_STATUS := 'REVOKED';
				END IF;
			END IF;
			IF l_root.TEST_WEBSITE_VALID_STATUS = 'OK' THEN
				t_temp := t_temp || '<A href="' || l_root.TEST_WEBSITE_VALID || '" target="_blank">URL</A>';
			ELSE
				t_temp := t_temp || '<A class="error" href="' || l_root.TEST_WEBSITE_VALID || '" target="_blank">' || l_root.TEST_WEBSITE_VALID_STATUS || '</A>';
			END IF;
		END IF;
		IF l_root.TEST_WEBSITE_VALID_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '&nbsp; <A href="/?id=' || l_root.TEST_WEBSITE_VALID_CERTIFICATE_ID::text || '&opt=ocsp" target="_blank">Cert</A>';
		END IF;

		t_temp := t_temp || '</TD>
    <TD>';
		IF (l_root.TEST_WEBSITE_EXPIRED IS NULL) OR (l_root.TEST_WEBSITE_EXPIRED_STATUS IS NULL) THEN
			t_temp := t_temp || '&nbsp;';
		ELSIF l_root.TEST_WEBSITE_EXPIRED_STATUS = 'Not checked' THEN
			t_temp := t_temp || '<FONT color="#888888">No URL available</FONT>';
		ELSIF l_root.TEST_WEBSITE_EXPIRED_STATUS = 'OK' THEN
			t_temp := t_temp || '<A href="' || l_root.TEST_WEBSITE_EXPIRED || '" target="_blank">URL</A>';
		ELSE
			t_temp := t_temp || '<A class="error" href="' || l_root.TEST_WEBSITE_EXPIRED || '" target="_blank">' || l_root.TEST_WEBSITE_EXPIRED_STATUS || '</A>';
		END IF;
		IF l_root.TEST_WEBSITE_EXPIRED_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '&nbsp; <A href="/?id=' || l_root.TEST_WEBSITE_EXPIRED_CERTIFICATE_ID::text || '&opt=ocsp" target="_blank">Cert</A>';
		END IF;

		t_temp := t_temp || '</TD>
    <TD>';
		IF (l_root.TEST_WEBSITE_REVOKED IS NULL) OR (l_root.TEST_WEBSITE_REVOKED_STATUS IS NULL) THEN
			t_temp := t_temp || '&nbsp;';
		ELSIF l_root.TEST_WEBSITE_EXPIRED_STATUS = 'Not checked' THEN
			t_temp := t_temp || '<FONT color="#888888">No URL available</FONT>';
		ELSE
			IF l_root.TEST_WEBSITE_REVOKED_STATUS = 'OK' THEN
				SELECT count(*)
					INTO t_count
					FROM certificate c, crl_revoked cr
					WHERE c.ID = l_root.TEST_WEBSITE_REVOKED_CERTIFICATE_ID
						AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
						AND c.ISSUER_CA_ID = cr.CA_ID;
				IF t_count = 0 THEN
					l_root.TEST_WEBSITE_REVOKED_STATUS := 'NOT REVOKED';
				END IF;
			END IF;
			IF l_root.TEST_WEBSITE_REVOKED_STATUS = 'OK' THEN
				t_temp := t_temp || '<A href="' || l_root.TEST_WEBSITE_REVOKED || '" target="_blank">URL</A>';
			ELSE
				t_temp := t_temp || '<A class="error" href="' || l_root.TEST_WEBSITE_REVOKED || '" target="_blank">' || l_root.TEST_WEBSITE_REVOKED_STATUS || '</A>';
			END IF;
		END IF;
		IF l_root.TEST_WEBSITE_REVOKED_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '&nbsp; <A href="/?id=' || l_root.TEST_WEBSITE_REVOKED_CERTIFICATE_ID::text || '&opt=ocsp" target="_blank">Cert</A>';
		END IF;

		t_output := t_output || t_temp || '</TD>
';
	END LOOP;

	RETURN t_output ||
'</TABLE>
';
END;
$$ LANGUAGE plpgsql;
