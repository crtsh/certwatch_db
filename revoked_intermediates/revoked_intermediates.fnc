CREATE OR REPLACE FUNCTION revoked_intermediates(
) RETURNS text
AS $$
DECLARE
	t_output				text;
	t_ctp					ca_trust_purpose%ROWTYPE;
	t_ctp2					ca_trust_purpose%ROWTYPE;
	t_ctp3					ca_trust_purpose%ROWTYPE;
	t_count					bigint;
	t_count2				bigint;
	t_temp					text;
	t_counts				bigint[][];
	t_counts_totals			bigint[][] := array_fill(0, ARRAY[5, 8]);
	l_record				RECORD;
BEGIN
	t_output :=
'  <SPAN class="whiteongrey">Revoked Intermediate CA Certificates with id-kp-serverAuth Trust</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH rowspan="2">Issuer</TH>
    <TH rowspan="2">Certificate</TH>
    <TH>The CA</TH>
    <TH>Microsoft</TH>
    <TH colspan="2">Mozilla</TH>
    <TH>Google</TH>
  </TR>
  <TR>
    <TH>CRL</TH>
    <TH>IE/Edge with<BR>disallowedcert.stl</TH>
    <TH>Firefox with<BR>OneCRL</TH>
    <TH>CCADB disclosure</TH>
    <TH>Chrome with<BR>CRLSet / Blacklist</TH>
  </TR>
';

	FOR l_record IN (
				SELECT c.ID, c.ISSUER_CA_ID, x509_notAfter(c.CERTIFICATE) NOT_AFTER,
						is_technically_constrained(c.CERTIFICATE) IS_TECHNICALLY_CONSTRAINED,
						get_ca_name_attribute(cac.CA_ID) SUBJECT_FRIENDLY_NAME,
						get_ca_name_attribute(c.ISSUER_CA_ID) ISSUER_FRIENDLY_NAME,
						md.CERTIFICATE_ID MS_CERTIFICATE_ID,
						mo.CERTIFICATE_ID MOZ_CERTIFICATE_ID,
						gr.ENTRY_TYPE, cr.SERIAL_NUMBER,
						cc.MOZILLA_DISCLOSURE_STATUS, cc.MICROSOFT_DISCLOSURE_STATUS,
						cc.REVOCATION_STATUS
					FROM ca_certificate cac, certificate c
						LEFT OUTER JOIN microsoft_disallowedcert md ON (c.ID = md.CERTIFICATE_ID)
						LEFT OUTER JOIN mozilla_onecrl mo ON (c.ID = mo.CERTIFICATE_ID)
						LEFT OUTER JOIN ccadb_certificate cc ON (c.ID = cc.CERTIFICATE_ID)
						LEFT OUTER JOIN google_revoked gr ON (c.ID = gr.CERTIFICATE_ID)
						LEFT OUTER JOIN crl_revoked cr ON (
							c.ISSUER_CA_ID = cr.CA_ID
							AND x509_serialNumber(c.CERTIFICATE) = cr.SERIAL_NUMBER
						)
					WHERE cac.CERTIFICATE_ID = c.ID
					ORDER BY ISSUER_FRIENDLY_NAME, SUBJECT_FRIENDLY_NAME, c.ID
			) LOOP
		SELECT ctp.*
			INTO t_ctp
			FROM ca_trust_purpose ctp
			WHERE ctp.CA_ID = l_record.ISSUER_CA_ID
				AND ctp.TRUST_CONTEXT_ID = 1
				AND ctp.TRUST_PURPOSE_ID = 1;
		SELECT ctp.*
			INTO t_ctp2
			FROM ca_trust_purpose ctp
			WHERE ctp.CA_ID = l_record.ISSUER_CA_ID
				AND ctp.TRUST_CONTEXT_ID = 5
				AND ctp.TRUST_PURPOSE_ID = 1;
		SELECT ctp.*
			INTO t_ctp3
			FROM ca_trust_purpose ctp
			WHERE ctp.CA_ID = l_record.ISSUER_CA_ID
				AND ctp.TRUST_CONTEXT_ID = 12
				AND ctp.TRUST_PURPOSE_ID = 1;

		t_count := 4;
		t_count2 := 0;
		t_counts := array_fill(0, ARRAY[5, 8]);
		t_temp :=
'  <TR>
    <TD><A href="/?caID=' || l_record.ISSUER_CA_ID::text || '">' || coalesce(l_record.ISSUER_FRIENDLY_NAME, '?') || '</A></TD>
    <TD><A href="/?id=' || l_record.ID::text || '">' || coalesce(l_record.SUBJECT_FRIENDLY_NAME, '?') || '</A></TD>
    <TD style="color:';
		IF l_record.SERIAL_NUMBER IS NOT NULL THEN
			t_temp := t_temp || '00CC00">Revoked';
			t_count2 := t_count2 + 1;
			t_counts[1][5] := 1;
		ELSIF l_record.NOT_AFTER < statement_timestamp() THEN
			t_temp := t_temp || '888888">Expired';
			t_counts[1][3] := 1;
		ELSE
			t_temp := t_temp || 'CC0000">Valid';
			t_counts[1][8] := 1;
		END IF;
		t_temp := t_temp || '</TD>
    <TD style="color:';
		IF l_record.MS_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '00CC00">Revoked';
			t_count2 := t_count2 + 1;
			t_counts[2][5] := 1;
		ELSIF t_ctp.CA_ID IS NULL THEN
			t_temp := t_temp || '888888">Untrusted';
			t_count := t_count - 1;
			t_counts[2][7] := 1;
		ELSIF (l_record.NOT_AFTER < statement_timestamp()) OR (NOT t_ctp.IS_TIME_VALID) THEN
			t_temp := t_temp || '888888">Expired';
			t_counts[2][3] := 1;
		ELSIF t_ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL THEN
			t_temp := t_temp || '00CC00">ParentRevoked';
			t_counts[2][4] := 1;
		ELSIF t_ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED OR l_record.IS_TECHNICALLY_CONSTRAINED THEN
			t_temp := t_temp || '888888">Constrained';
			t_counts[2][1] := 1;
		ELSE
			t_temp := t_temp || 'CC0000">Valid';
			t_counts[2][8] := 1;
		END IF;
		t_temp := t_temp || '</TD>
    <TD style="color:';
		IF l_record.MOZ_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '00CC00">Revoked';
			t_count2 := t_count2 + 1;
			t_counts[3][5] := 1;
		ELSIF t_ctp2.CA_ID IS NULL THEN
			t_temp := t_temp || '888888">Untrusted';
			t_count := t_count - 1;
			t_counts[3][7] := 1;
		ELSIF (l_record.NOT_AFTER < statement_timestamp()) OR (NOT t_ctp2.IS_TIME_VALID) THEN
			t_temp := t_temp || '888888">Expired';
			t_counts[3][3] := 1;
		ELSIF t_ctp2.ALL_CHAINS_REVOKED_VIA_ONECRL THEN
			t_temp := t_temp || '00CC00">ParentRevoked';
			t_counts[3][4] := 1;
		ELSIF t_ctp2.ALL_CHAINS_TECHNICALLY_CONSTRAINED OR l_record.IS_TECHNICALLY_CONSTRAINED THEN
			t_temp := t_temp || '888888">Constrained';
			t_counts[3][1] := 1;
		ELSE
			t_temp := t_temp || 'CC0000">Valid';
			t_counts[3][8] := 1;
		END IF;
		t_temp := t_temp || '</TD>
    <TD style="color:';
		IF (l_record.MOZILLA_DISCLOSURE_STATUS::text LIKE 'Disclos%')
				OR (l_record.MICROSOFT_DISCLOSURE_STATUS::text LIKE 'Disclos%') THEN
			t_temp := t_temp || 'CC0000">Disclosed';
			t_counts[4][2] := 1;
		ELSIF l_record.REVOCATION_STATUS = 'Revoked' THEN
			t_temp := t_temp || '00CC00">Revoked';
			t_count2 := t_count2 + 1;
			t_counts[4][5] := 1;
		ELSIF l_record.REVOCATION_STATUS = 'Parent Cert Revoked' THEN
			t_temp := t_temp || '00CC00">ParentRevoked';
			t_count2 := t_count2 + 1;
			t_counts[4][4] := 1;
		ELSIF t_ctp2.CA_ID IS NULL THEN
			t_temp := t_temp || '888888">Untrusted';
			t_count := t_count - 1;
			t_counts[4][7] := 1;
		ELSIF (l_record.NOT_AFTER < statement_timestamp()) OR (NOT t_ctp2.IS_TIME_VALID) THEN
			t_temp := t_temp || '888888">Expired';
			t_counts[4][3] := 1;
		ELSIF t_ctp2.ALL_CHAINS_TECHNICALLY_CONSTRAINED OR l_record.IS_TECHNICALLY_CONSTRAINED THEN
			t_temp := t_temp || '888888">Constrained';
			t_counts[4][1] := 1;
		ELSE
			t_temp := t_temp || 'CC0000">Undisclosed';
			t_counts[4][6] := 1;
		END IF;
		t_temp := t_temp || '</TD>
    <TD style="color:';
		IF l_record.ENTRY_TYPE IS NOT NULL THEN
			t_temp := t_temp || '00CC00">Revoked';
			t_count2 := t_count2 + 1;
			t_counts[5][5] := 1;
		ELSIF (t_ctp.CA_ID IS NULL) AND (t_ctp2.CA_ID IS NULL) AND (t_ctp3.CA_ID IS NULL) THEN
			t_temp := t_temp || '888888">Untrusted';
			t_count := t_count - 1;
			t_counts[5][7] := 1;
		ELSIF l_record.NOT_AFTER < statement_timestamp() OR ((NOT t_ctp.IS_TIME_VALID) AND (NOT t_ctp2.IS_TIME_VALID) OR (NOT t_ctp3.IS_TIME_VALID)) THEN
			t_temp := t_temp || '888888">Expired';
			t_counts[5][3] := 1;
		ELSIF t_ctp.ALL_CHAINS_REVOKED_VIA_CRLSET AND t_ctp2.ALL_CHAINS_REVOKED_VIA_CRLSET AND t_ctp3.ALL_CHAINS_REVOKED_VIA_CRLSET THEN
			t_temp := t_temp || '00CC00">ParentRevoked';
			t_counts[5][4] := 1;
		ELSIF (t_ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED AND t_ctp2.ALL_CHAINS_TECHNICALLY_CONSTRAINED AND t_ctp3.ALL_CHAINS_TECHNICALLY_CONSTRAINED) OR l_record.IS_TECHNICALLY_CONSTRAINED THEN
			t_temp := t_temp || '888888">Constrained';
			t_counts[5][1] := 1;
		ELSE
			t_temp := t_temp || 'CC0000">Valid';
			t_counts[5][8] := 1;
		END IF;
		t_temp := t_temp || '</TD>
  </TR>
';
		IF (t_count > 0) AND (t_count2 > 0) THEN
			t_output := t_output || t_temp;
			FOR i IN 1..5 LOOP
				FOR j IN 1..8 LOOP
					t_counts_totals[i][j] := t_counts_totals[i][j] + t_counts[i][j];
				END LOOP;
			END LOOP;
		END IF;
	END LOOP;

	t_output := t_output ||
'  <TR>
    <TD colspan="2" style="text-align:right">Total Constrained:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][1]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Disclosed:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][2]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Expired:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][3]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total ParentRevoked:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][4]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Revoked:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][5]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Undisclosed:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][6]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Untrusted:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][7]::text || '</TD>
';
	END LOOP;
	t_output := t_output ||
'  </TR>
  <TR>
    <TD colspan="2" style="text-align:right">Total Valid:</TD>
';
	FOR i IN 1..5 LOOP
		t_output := t_output ||
'    <TD>' || t_counts_totals[i][8]::text || '</TD>
';
	END LOOP;

	RETURN t_output ||
'  </TR>
</TABLE>
';
END;
$$ LANGUAGE plpgsql;

