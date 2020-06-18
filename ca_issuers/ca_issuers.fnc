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

CREATE OR REPLACE FUNCTION ca_issuers(
	dir						text,
	sort					integer,
	rootOwner				text,
	url						text,
	contentOrError			text,
	contentType				text,
	trustedBy				text,
	trustedFor				text,
	trustedExclude			text
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
	t_caOwners				text;
	l_record				RECORD;
	l_record2				RECORD;
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
	IF coalesce(trustedFor, '') != '' THEN
		t_params := t_params || '&trustedFor=' || trustedFor;
	ELSE
		trustedFor := NULL;
	END IF;
	IF coalesce(trustedExclude, '') != '' THEN
		t_params := t_params || '&trustedExclude=' || trustedExclude;
	ELSE
		trustedExclude := NULL;
	END IF;

	t_query :=
'SELECT get_ca_name_attribute(cais.CA_ID) CA_FRIENDLY_NAME, cais.*
	FROM ca_issuer cais
	WHERE cais.CA_ID != -1
		AND cais.IS_ACTIVE
';
	IF coalesce(url, '') != '' THEN
		t_query := t_query ||
'		AND cais.URL ILIKE ' || quote_literal(url) || '
';
		t_params := t_params || '&url=' || urlEncode(url);
	END IF;
	IF coalesce(contentOrError, '') != '' THEN
		t_query := t_query ||
'		AND cais.RESULT ILIKE ' || quote_literal(contentOrError) || '
';
		t_params := t_params || '&content=' || urlEncode(contentOrError);
	END IF;
	IF coalesce(contentType, '') != '' THEN
		t_query := t_query ||
'		AND cais.CONTENT_TYPE ILIKE ' || quote_literal(contentType) || '
';
		t_params := t_params || '&contentType=' || urlEncode(contentType);
	END IF;

	IF (trustedBy IS NOT NULL) OR (trustedFor IS NOT NULL) OR (trustedExclude IS NOT NULL) THEN
		t_query := t_query ||
'		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp, trust_context tc, trust_purpose tp
				WHERE ctp.CA_ID = cais.CA_ID
					AND ctp.TRUST_CONTEXT_ID = tc.ID
					AND tc.CTX = ' || coalesce(quote_literal(trustedBy), 'tc.CTX') || '
					AND ctp.TRUST_PURPOSE_ID = tp.ID
					AND tp.PURPOSE = ' || coalesce(quote_literal(trustedFor), 'tp.PURPOSE') || '
';
		IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,constrained,%' THEN
			t_query := t_query ||
'					AND NOT ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
';
		END IF;
		IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,expired,%' THEN
			t_query := t_query ||
'					AND ctp.IS_TIME_VALID
';
		END IF;
		IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,onecrl,%' THEN
			t_query := t_query ||
'					AND NOT ctp.ALL_CHAINS_REVOKED_VIA_ONECRL
';
		END IF;
		IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,crlset,%' THEN
			t_query := t_query ||
'					AND NOT ctp.ALL_CHAINS_REVOKED_VIA_CRLSET
';
		END IF;
		IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,disallowedstl,%' THEN
			t_query := t_query ||
'					AND NOT ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
';
		END IF;
		t_query := t_query ||
'		)
';
	END IF;
	t_query := t_query ||
'	ORDER BY ' || CASE sort
					WHEN 2 THEN 'CA_FRIENDLY_NAME' || t_orderBy || ', cais.URL' || t_orderBy
					WHEN 3 THEN 'cais.URL' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy
				END;

	IF coalesce(sort::text, '') != '' THEN
		t_paramsWithSort := t_params || '&sort=' || sort::text;
	ELSE
		sort := NULL;
	END IF;

	t_output :=
'  <SPAN class="whiteongrey">CA Issuers (Authority Info Access)</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<SCRIPT type="text/javascript">
  function submitForm(v_form) {
    if (document.getElementById("constrained").checked) {
      v_form.trustedExclude.value += ",constrained";
    }
    if (document.getElementById("expired").checked) {
      v_form.trustedExclude.value += ",expired";
    }
    if (document.getElementById("onecrl").checked) {
      v_form.trustedExclude.value += ",onecrl";
    }
    if (document.getElementById("crlset").checked) {
      v_form.trustedExclude.value += ",crlset";
    }
    if (document.getElementById("disallowedstl").checked) {
      v_form.trustedExclude.value += ",disallowedstl";
    }
    v_form.trustedExclude.value = v_form.trustedExclude.value.substr(1);
    return true;
  }
</SCRIPT>
<TABLE>
  <TR>
    <TH class="outer">Trust Filter<BR><BR><SPAN style="font-size:8pt;font-weight:normal;color:#888888">Configure for <A href="?webpki">WebPKI</A></TH>
    <TD class="outer">
      <TABLE>
        <TR>
          <TD><B>Exclude:</B></TD>
          <TD>
            <INPUT id="constrained" type="checkbox"';
	IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,constrained,%' THEN
		t_output := t_output || ' checked';
	END IF;
	t_output := t_output || '>Constrained
            &nbsp; <INPUT id="expired" type="checkbox"';
	IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,expired,%' THEN
		t_output := t_output || ' checked';
	END IF;
	t_output := t_output || '>Expired
            &nbsp; <INPUT id="onecrl" type="checkbox"';
	IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,onecrl,%' THEN
		t_output := t_output || ' checked';
	END IF;
	t_output := t_output || '>Revoked via <A href="/mozilla-onecrl" target="_blank">OneCRL</A>
            <BR><INPUT id="crlset" type="checkbox"';
	IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,crlset,%' THEN
		t_output := t_output || ' checked';
	END IF;
	t_output := t_output || '>Revoked via CRLSet
            &nbsp; <INPUT id="disallowedstl" type="checkbox"';
	IF (',' || coalesce(trustedExclude, '') || ',') ILIKE '%,disallowedstl,%' THEN
		t_output := t_output || ' checked';
	END IF;
	t_output := t_output || '>Revoked via disallowedcert.stl
          </TD>
        </TR>
        <TR>
          <TD>
            <FORM onsubmit="return submitForm(this)">
            <INPUT type="hidden" name="trustedExclude">
            <B>Include:</B>
          </TD>
          <TD>
            Trusted by
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
'              <OPTION value="' || coalesce(l_record.VALUE, '') || '"';
		IF trustedBy = l_record.VALUE THEN
			t_output := t_output || ' selected';
		END IF;
		t_output := t_output || '>' || l_record.CTX || '</OPTION>
';
	END LOOP;
	t_output := t_output || 
'            </SELECT>
            for
            <SELECT name="trustedFor">
';
	FOR l_record IN (
				SELECT ''		AS VALUE,
						'ANY'	AS PURPOSE,
						-2		AS DISPLAY_ORDER
				UNION
				SELECT NULL		AS VALUE,
						'--------------',
						-1		AS DISPLAY_ORDER
				UNION
				SELECT tp.PURPOSE	AS VALUE,
						tp.PURPOSE,
						tp.DISPLAY_ORDER
					FROM trust_purpose tp
					WHERE tp.ID < 100
				ORDER BY DISPLAY_ORDER
			) LOOP
		t_output := t_output ||
'              <OPTION value="' || coalesce(l_record.VALUE, '') || '"';
		IF trustedFor = l_record.VALUE THEN
			t_output := t_output || ' selected';
		END IF;
		t_output := t_output || '>' || l_record.PURPOSE || '</OPTION>
';
	END LOOP;
	t_output := t_output || 
'            </SELECT>
          </TD>
        </TR>
      </TABLE>
      <INPUT type="hidden" name="dir" value="' || html_escape(dir) || '">
      <INPUT type="hidden" name="sort" value="' || html_escape(sort::text) || '">
    </TD>
  </TR>
  <TR>
    <TH class="outer">Root Owner</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="rootOwner" size="55" value="' || coalesce(html_escape(rootOwner), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">CA Issuers URL</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="url" size="55" value="' || coalesce(html_escape(url), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">Content or Error</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="content" size="55" value="' || coalesce(html_escape(contentOrError), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">Content Type</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="contentType" size="55" value="' || coalesce(html_escape(contentType), '') || '"></TD>
  </TR>
  <TR>
    <TD class="small" style="text-align:center;vertical-align:middle">(% = wildcard)</TD>
    <TD class="outer"><INPUT type="submit" class="button" style="font-size:9pt" value="Update"></TD>
  </TR>
</FORM>
</TABLE>
<BR>
<TABLE>
  <TR>
    <TH>Root Owner(s)</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=2' || t_params || '">CA Name</A>';
	IF sort = 2 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=3' || t_params || '">CA Issuers URL</A>';
	IF sort = 3 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH>CA Issuers Certificate(s)</TH>
    <TH>Content or Error</TH>
    <TH>Content-Type</TH>
    <TH>First Cert Observed</TH>
  </TR>
';
	FOR l_record IN EXECUTE t_query LOOP
		SELECT array_to_string(array_agg(DISTINCT cc.INCLUDED_CERTIFICATE_OWNER ORDER BY cc.INCLUDED_CERTIFICATE_OWNER), '<HR>')
			INTO t_caOwners
			FROM ca_certificate cac, ccadb_certificate cc
			WHERE cac.CA_ID = l_record.CA_ID
				AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
				AND cc.INCLUDED_CERTIFICATE_OWNER IS NOT NULL;

		IF coalesce(rootOwner, '') != '' THEN
			IF (t_caOwners IS NULL) OR (t_caOwners NOT ILIKE ('%' || rootOwner || '%')) THEN
				CONTINUE;
			END IF;
		END IF;

		t_temp :=
'  <TR>
    <TD>' || coalesce(t_caOwners, '&nbsp;') || '</TD>
    <TD><A href="/?caID=' || l_record.CA_ID::text || '" target="_blank">' || html_escape(l_record.CA_FRIENDLY_NAME) || '</A></TD>
    <TD><A href="' || l_record.URL || '" target="_blank">';
		IF length(l_record.URL) < 64 THEN
			t_temp := t_temp || l_record.URL;
		ELSE
			t_temp := t_temp || substr(l_record.URL, 1, 61) || '...';
		END IF;
		t_temp := t_temp || '</A></TD>
    <TD>';
		IF array_length(l_record.CA_CERTIFICATE_IDS, 1) > 0 THEN
			FOR l_record2 IN (
				SELECT CERT_ID, cac.CA_ID
					FROM unnest(l_record.CA_CERTIFICATE_IDS) CERT_ID
							LEFT OUTER JOIN ca_certificate cac ON (
								CERT_ID = cac.CERTIFICATE_ID
								AND cac.CA_ID = l_record.CA_ID
							)
			) LOOP
				IF l_record2.CA_ID IS NOT NULL THEN
					t_temp := t_temp || '<A';
				ELSE
					t_temp := t_temp || '<A class="error"';
				END IF;
				t_temp := t_temp || ' href="/?id=' || l_record2.CERT_ID::text || '">' || l_record2.CERT_ID::text || '</A><BR>';
			END LOOP;
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF l_record.RESULT IN ('DER X.509', 'DER CMS') THEN
			t_temp := t_temp || '<SPAN>';
		ELSIF l_record.RESULT = 'Protocol not supported' THEN
			t_temp := t_temp || '<SPAN style="color:#888888">';
		ELSE
			t_temp := t_temp || '<SPAN class="error">';
		END IF;
		t_temp := t_temp || coalesce(l_record.RESULT, '&nbsp;') || '</SPAN></TD>
    <TD>';
		IF ((l_record.CONTENT_TYPE = 'application/pkix-cert') AND (l_record.RESULT IN ('DER X.509', 'PEM X.509')))
				OR ((l_record.CONTENT_TYPE = 'application/pkcs7-mime') AND (l_record.RESULT IN ('DER CMS', 'PEM CMS'))) THEN
			t_temp := t_temp || l_record.CONTENT_TYPE;
		ELSE
			t_temp := t_temp || '<SPAN class="error">' || coalesce(l_record.CONTENT_TYPE, '&nbsp;') || '</SPAN>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF l_record.FIRST_CERTIFICATE_ID IS NOT NULL THEN
			t_temp := t_temp || '<A href="/?id=' || l_record.FIRST_CERTIFICATE_ID::text || '" target="_blank">' || l_record.FIRST_CERTIFICATE_ID::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
  </TR>
';

		t_output := t_output || t_temp;
	END LOOP;

	t_output := t_output ||
'</TABLE>
';

	RETURN t_output;
END;
$$ LANGUAGE plpgsql;
