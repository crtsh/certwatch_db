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

CREATE OR REPLACE FUNCTION test_websites(
	dir						text,
	sort					integer,
	trustedBy				text,
	caOwner					text
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
	t_thisUpdate			crl.THIS_UPDATE%TYPE;
	t_nextUpdate			crl.NEXT_UPDATE%TYPE;
	t_lastChecked			crl.LAST_CHECKED%TYPE;
	t_lastSeenCheckDate		crl_revoked.LAST_SEEN_CHECK_DATE%TYPE;
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
		cc.TEST_WEBSITE_REVOKED, cc.TEST_WEBSITE_REVOKED_STATUS, cc.TEST_WEBSITE_REVOKED_CERTIFICATE_ID,
		crev.ISSUER_CA_ID ISSUER_CA_ID_REVOKED, x509_serialNumber(crev.CERTIFICATE) SERIAL_NUMBER_REVOKED
	FROM ccadb_certificate cc
			LEFT OUTER JOIN certificate crev ON (cc.TEST_WEBSITE_REVOKED_CERTIFICATE_ID = crev.ID)
			LEFT OUTER JOIN certificate c ON (cc.CERTIFICATE_ID = c.ID)
	WHERE cc.CERT_RECORD_TYPE = ''Root Certificate''
		AND coalesce(x509_notAfter(c.CERTIFICATE), ''infinity''::timestamp) > now() AT TIME ZONE ''UTC''';
	IF trustedBy IS NOT NULL THEN
		t_query := t_query || '
		AND EXISTS (
			SELECT 1
				FROM root_trust_purpose rtp, trust_context tc
				WHERE cc.CERTIFICATE_ID = rtp.CERTIFICATE_ID
					AND rtp.TRUST_PURPOSE_ID = 1	-- Server Authentication.
					AND rtp.TRUST_CONTEXT_ID = tc.ID
					AND tc.CTX = ' || coalesce(quote_literal(trustedBy), 'tc.CTX') || '
		)';
	END IF;
	IF caOwner IS NOT NULL THEN
		t_query := t_query || '
		AND cc.INCLUDED_CERTIFICATE_OWNER = ' || coalesce(quote_literal(caOwner));
	END IF;
	t_query := t_query || '
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
    <TD>';
		IF l_root.CA_OWNER IS NOT NULL THEN
			t_temp := t_temp || '<A href="?caOwner=' || l_root.CA_OWNER || '&dir=' || dir || '&sort=' || sort || t_params || '">' || coalesce(l_root.CA_OWNER) || '</A></TD>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF l_root.CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '<A href="/?id=' || l_root.CERTIFICATE_ID::text || '" target="_blank">' || l_root.CERT_NAME || '</A>';
		ELSE
			t_temp := t_temp || l_root.CERT_NAME;
		END IF;
		t_temp := t_temp || '</TD>
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
					l_root.TEST_WEBSITE_VALID_STATUS := 'Revoked';
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
		ELSIF l_root.TEST_WEBSITE_REVOKED_STATUS = 'Not checked' THEN
			t_temp := t_temp || '<FONT color="#888888">No URL available</FONT>';
		ELSE
			IF l_root.TEST_WEBSITE_REVOKED_STATUS = 'OK' THEN
				SELECT crl.THIS_UPDATE, crl.NEXT_UPDATE, crl.LAST_CHECKED
					INTO t_thisUpdate, t_nextUpdate, t_lastChecked
					FROM crl
					WHERE crl.CA_ID = l_root.ISSUER_CA_ID_REVOKED
					ORDER BY (crl.ERROR_MESSAGE IS NULL) DESC, crl.LAST_CHECKED DESC
					LIMIT 1;
				IF FOUND THEN
					IF t_nextUpdate < statement_timestamp() AT TIME ZONE 'UTC' THEN
						l_root.TEST_WEBSITE_REVOKED_STATUS := 'CRL Expired';
					ELSE
						SELECT max(cr.LAST_SEEN_CHECK_DATE)
							INTO t_lastSeenCheckDate
							FROM crl_revoked cr
							WHERE cr.SERIAL_NUMBER = l_root.SERIAL_NUMBER_REVOKED
								AND cr.CA_ID = l_root.ISSUER_CA_ID_REVOKED;
						IF t_lastSeenCheckDate IS NULL THEN
							l_root.TEST_WEBSITE_REVOKED_STATUS := 'Not on CRL';
						ELSIF t_lastSeenCheckDate < t_thisUpdate THEN
							l_root.TEST_WEBSITE_REVOKED_STATUS := 'Removed from CRL';
						END IF;
					END IF;
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
