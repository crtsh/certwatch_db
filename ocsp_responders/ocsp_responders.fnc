/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2021 Sectigo Limited
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

CREATE OR REPLACE FUNCTION ocsp_responders(
	dir						text,
	sort					integer,
	url						text,
	trustedBy				text,
	trustedFor				text,
	trustedExclude			text,
	get						text,
	post					text,
	getrandomserial			text,
	postrandomserial		text,
	getforwardslashes		text
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
'SELECT get_ca_name_attribute(orp.CA_ID) CA_FRIENDLY_NAME, orp.*
	FROM ocsp_responder orp
	WHERE orp.CA_ID != -1
';
	IF coalesce(url, '') != '' THEN
		t_query := t_query ||
'		AND orp.URL ILIKE ' || quote_literal(url) || '
';
		t_params := t_params || '&url=' || urlEncode(url);
	END IF;

	IF (trustedBy IS NOT NULL) OR (trustedFor IS NOT NULL) OR (trustedExclude IS NOT NULL) THEN
		t_query := t_query ||
'		AND EXISTS (
			SELECT 1
				FROM ca_trust_purpose ctp, trust_context tc, trust_purpose tp
				WHERE ctp.CA_ID = orp.CA_ID
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
	IF coalesce(get, '') != '' THEN
		t_query := t_query ||
'		AND orp.GET_RESULT ILIKE ' || quote_literal(get) || '
';
		t_params := t_params || '&get=' || urlEncode(get);
	END IF;
	IF coalesce(post, '') != '' THEN
		t_query := t_query ||
'		AND orp.POST_RESULT ILIKE ' || quote_literal(post) || '
';
		t_params := t_params || '&post=' || urlEncode(post);
	END IF;
	IF coalesce(getrandomserial, '') != '' THEN
		t_query := t_query ||
'		AND orp.GET_RANDOM_SERIAL_RESULT ILIKE ' || quote_literal(getrandomserial) || '
';
		t_params := t_params || '&getrandomserial=' || urlEncode(getrandomserial);
	END IF;
	IF coalesce(postrandomserial, '') != '' THEN
		t_query := t_query ||
'		AND orp.POST_RANDOM_SERIAL_RESULT ILIKE ' || quote_literal(postrandomserial) || '
';
		t_params := t_params || '&postrandomserial=' || urlEncode(postrandomserial);
	END IF;
	IF coalesce(getforwardslashes, '') != '' THEN
		t_query := t_query ||
'		AND orp.FORWARD_SLASHES_RESULT ILIKE ' || quote_literal(getforwardslashes) || '
';
		t_params := t_params || '&getforwardslashes=' || urlEncode(getforwardslashes);
	END IF;
	t_query := t_query ||
'	ORDER BY ' || CASE sort
					WHEN 2 THEN 'CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 3 THEN 'orp.URL' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy
					WHEN 5 THEN 'CASE WHEN length(orp.GET_DUMP) = 0 THEN 1 ELSE 0 END, orp.GET_RESULT' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 6 THEN 'CASE WHEN length(orp.GET_DUMP) = 0 THEN 1 ELSE 0 END, length(orp.GET_DUMP)' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 7 THEN 'CASE WHEN length(orp.GET_DUMP) = 0 THEN 1 ELSE 0 END, orp.GET_DURATION' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 8 THEN 'CASE WHEN length(orp.POST_DUMP) = 0 THEN 1 ELSE 0 END, orp.POST_RESULT' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 9 THEN 'CASE WHEN length(orp.POST_DUMP) = 0 THEN 1 ELSE 0 END, length(orp.POST_DUMP)' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 10 THEN 'CASE WHEN length(orp.POST_DUMP) = 0 THEN 1 ELSE 0 END, orp.POST_DURATION' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 11 THEN 'CASE WHEN length(orp.GET_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, orp.GET_RANDOM_SERIAL_RESULT' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 12 THEN 'CASE WHEN length(orp.GET_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, length(orp.GET_RANDOM_SERIAL_DUMP)' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 13 THEN 'CASE WHEN length(orp.GET_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, orp.GET_RANDOM_SERIAL_DURATION' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 14 THEN 'CASE WHEN length(orp.POST_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, orp.POST_RANDOM_SERIAL_RESULT' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 15 THEN 'CASE WHEN length(orp.POST_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, length(orp.POST_RANDOM_SERIAL_DUMP)' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 16 THEN 'CASE WHEN length(orp.POST_RANDOM_SERIAL_DUMP) = 0 THEN 1 ELSE 0 END, orp.POST_RANDOM_SERIAL_DURATION' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 17 THEN 'CASE WHEN length(orp.FORWARD_SLASHES_DUMP) = 0 THEN 1 ELSE 0 END, orp.FORWARD_SLASHES_RESULT' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 18 THEN 'CASE WHEN length(orp.FORWARD_SLASHES_DUMP) = 0 THEN 1 ELSE 0 END, length(orp.FORWARD_SLASHES_DUMP)' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
					WHEN 19 THEN 'CASE WHEN length(orp.FORWARD_SLASHES_DUMP) = 0 THEN 1 ELSE 0 END, orp.FORWARD_SLASHES_DURATION' || t_orderBy || ', CA_FRIENDLY_NAME' || t_orderBy || ', orp.URL' || t_orderBy
				END;

	IF coalesce(sort::text, '') != '' THEN
		t_paramsWithSort := t_params || '&sort=' || sort::text;
	ELSE
		sort := NULL;
	END IF;

	t_output :=
'  <SPAN class="whiteongrey">OCSP Responders</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
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
    <TH class="outer">Responder URL</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="url" size="55" value="' || coalesce(html_escape(url), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">GET request for Certificate</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="get" size="55" value="' || coalesce(html_escape(get), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">POST request for Certificate</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="post" size="55" value="' || coalesce(html_escape(post), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">GET request for Random Serial</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="getrandomserial" size="55" value="' || coalesce(html_escape(getrandomserial), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">POST request for Random Serial</TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="postrandomserial" size="55" value="' || coalesce(html_escape(postrandomserial), '') || '"></TD>
  </TR>
  <TR>
    <TH class="outer">GET request containing <A href="//groups.google.com/a/mozilla.org/g/dev-security-policy/c/cMegyySSqhM/m/G7s5tFR4BAAJ" target="_blank">multiple forward-slashes</A></TH>
    <TD class="outer"><INPUT style="border:none;background-color:#EFEFEF" type="text" name="getforwardslashes" size="55" value="' || coalesce(html_escape(getforwardslashes), '') || '"></TD>
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
    <TH rowspan="2">Root Owner(s)</TH>
    <TH rowspan="2"><A href="?dir=' || t_oppositeDirection || '&sort=2' || t_params || '">CA Name</A>';
	IF sort = 2 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH rowspan="2"><A href="?dir=' || t_oppositeDirection || '&sort=3' || t_params || '">Responder URL</A>';
	IF sort = 3 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH rowspan="2">Certificate Used</TH>
    <TH colspan="3">GET request for Certificate</TH>
    <TH colspan="3">POST request for Certificate</TH>
    <TH colspan="3">GET request for Random Serial</TH>
    <TH colspan="3">POST request for Random Serial</TH>
    <TH colspan="3">GET request containing multiple forward-slashes</TH>
  </TR>
  <TR>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=5' || t_params || '">Response</A>';
	IF sort = 5 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=6' || t_params || '">B</A>';
	IF sort = 6 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=7' || t_params || '">ms</A>';
	IF sort = 7 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=8' || t_params || '">Response</A>';
	IF sort = 8 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=9' || t_params || '">B</A>';
	IF sort = 9 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=10' || t_params || '">ms</A>';
	IF sort = 10 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=11' || t_params || '">Response</A>';
	IF sort = 11 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=12' || t_params || '">B</A>';
	IF sort = 12 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=13' || t_params || '">ms</A>';
	IF sort = 13 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=14' || t_params || '">Response</A>';
	IF sort = 14 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=15' || t_params || '">B</A>';
	IF sort = 15 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=16' || t_params || '">ms</A>';
	IF sort = 16 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=17' || t_params || '">Response</A>';
	IF sort = 17 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=18' || t_params || '">B</A>';
	IF sort = 18 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
    <TH><A href="?dir=' || t_oppositeDirection || '&sort=19' || t_params || '">ms</A>';
	IF sort = 19 THEN
		t_output := t_output || ' ' || t_dirSymbol;
	END IF;
	t_output := t_output || '</TH>
  </TR>
';
	FOR l_record IN EXECUTE t_query LOOP
		SELECT array_to_string(array_agg(DISTINCT cc.INCLUDED_CERTIFICATE_OWNER ORDER BY cc.INCLUDED_CERTIFICATE_OWNER), '<BR>')
			INTO t_caOwners
			FROM ca_certificate cac, ccadb_certificate cc
			WHERE cac.CA_ID = l_record.CA_ID
				AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
				AND cc.INCLUDED_CERTIFICATE_OWNER IS NOT NULL;
		t_temp :=
'  <TR>
    <TD>' || coalesce(t_caOwners, '&nbsp;') || '</TD>
    <TD><A href="/?caID=' || l_record.CA_ID::text || '" target="_blank">' || html_escape(l_record.CA_FRIENDLY_NAME) || '</A></TD>
    <TD><A title="' || l_record.URL || '">';

		IF length(l_record.URL) < 48 THEN
			t_temp := t_temp || l_record.URL;
		ELSE
			t_temp := t_temp || substr(l_record.URL, 1, 45) || '...';
		END IF;
		t_temp := t_temp || '</A></TD>
    <TD>';
		IF l_record.TESTED_CERTIFICATE_ID IS NULL THEN
			t_temp := t_temp || '<I>None</I>';
		ELSE
			t_temp := t_temp || '<A href="/?id=' || l_record.TESTED_CERTIFICATE_ID::text || '" target="_blank">' || l_record.TESTED_CERTIFICATE_ID::text || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';

		IF l_record.GET_RESULT IS NULL THEN
			t_temp := t_temp || '<I>Not tested</I>';
		ELSE
			IF l_record.GET_RESULT LIKE 'Revoked|%' THEN
				l_record.GET_RESULT := 'Revoked at ' || substring(l_record.GET_RESULT from 9 for (length(l_record.GET_RESULT) - 10));
			END IF;
			t_temp := t_temp || '<A href="?get=' || urlEncode(l_record.GET_RESULT) || t_paramsWithSort || t_baseParams || '">' || html_escape(l_record.GET_RESULT) || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF coalesce(length(l_record.GET_DUMP), 0) > 0 THEN
			t_temp := t_temp || '<A href="/ocsp-response?caID=' || l_record.CA_ID::text || '&url=' || urlEncode(l_record.URL) || '&request=get" target="_blank">' || length(l_record.GET_DUMP)::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>' || coalesce((l_record.GET_DURATION / 1000000)::text, '&nbsp;') || '</TD>
    <TD>';

		IF l_record.POST_RESULT IS NULL THEN
			t_temp := t_temp || '<I>Not tested</I>';
		ELSE
			IF l_record.POST_RESULT LIKE 'Revoked|%' THEN
				l_record.POST_RESULT := 'Revoked at ' || substring(l_record.POST_RESULT from 9 for (length(l_record.POST_RESULT) - 10));
			END IF;
			t_temp := t_temp || '<A href="?post=' || urlEncode(l_record.POST_RESULT) || t_paramsWithSort || t_baseParams || '">' || html_escape(l_record.POST_RESULT) || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF coalesce(length(l_record.POST_DUMP), 0) > 0 THEN
			t_temp := t_temp || '<A href="/ocsp-response?caID=' || l_record.CA_ID::text || '&url=' || urlEncode(l_record.URL) || '&request=post" target="_blank">' || length(l_record.POST_DUMP)::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>' || coalesce((l_record.POST_DURATION / 1000000)::text, '&nbsp;') || '</TD>
    <TD>';

		IF l_record.GET_RANDOM_SERIAL_RESULT IS NULL THEN
			t_temp := t_temp || '<I>Not tested</I>';
		ELSE
			IF l_record.GET_RANDOM_SERIAL_RESULT LIKE 'Revoked|%' THEN
				l_record.GET_RANDOM_SERIAL_RESULT := 'Revoked at ' || substring(l_record.GET_RANDOM_SERIAL_RESULT from 9 for (length(l_record.GET_RANDOM_SERIAL_RESULT) - 10));
			END IF;
			t_temp := t_temp || '<A href="?getrandomserial=' || urlEncode(l_record.GET_RANDOM_SERIAL_RESULT) || t_paramsWithSort || t_baseParams || '">' || html_escape(l_record.GET_RANDOM_SERIAL_RESULT) || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF coalesce(length(l_record.GET_RANDOM_SERIAL_DUMP), 0) > 0 THEN
			t_temp := t_temp || '<A href="/ocsp-response?caID=' || l_record.CA_ID::text || '&url=' || urlEncode(l_record.URL) || '&request=getrandomserial" target="_blank">' || length(l_record.GET_RANDOM_SERIAL_DUMP)::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>' || coalesce((l_record.GET_RANDOM_SERIAL_DURATION / 1000000)::text, '&nbsp;') || '</TD>
    <TD>';

		IF l_record.POST_RANDOM_SERIAL_RESULT IS NULL THEN
			t_temp := t_temp || '<I>Not tested</I>';
		ELSE
			IF l_record.POST_RANDOM_SERIAL_RESULT LIKE 'Revoked|%' THEN
				l_record.POST_RANDOM_SERIAL_RESULT := 'Revoked at ' || substring(l_record.POST_RANDOM_SERIAL_RESULT from 9 for (length(l_record.POST_RANDOM_SERIAL_RESULT) - 10));
			END IF;
			t_temp := t_temp || '<A href="?postrandomserial=' || urlEncode(l_record.POST_RANDOM_SERIAL_RESULT) || t_paramsWithSort || t_baseParams || '">' || html_escape(l_record.POST_RANDOM_SERIAL_RESULT) || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF coalesce(length(l_record.POST_RANDOM_SERIAL_DUMP), 0) > 0 THEN
			t_temp := t_temp || '<A href="/ocsp-response?caID=' || l_record.CA_ID::text || '&url=' || urlEncode(l_record.URL) || '&request=postrandomserial" target="_blank">' || length(l_record.POST_RANDOM_SERIAL_DUMP)::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>' || coalesce((l_record.POST_RANDOM_SERIAL_DURATION / 1000000)::text, '&nbsp;') || '</TD>
    <TD>';

		IF l_record.FORWARD_SLASHES_RESULT IS NULL THEN
			t_temp := t_temp || '<I>Not tested</I>';
		ELSE
			IF l_record.FORWARD_SLASHES_RESULT LIKE 'Revoked|%' THEN
				l_record.FORWARD_SLASHES_RESULT := 'Revoked at ' || substring(l_record.FORWARD_SLASHES_RESULT from 9 for (length(l_record.FORWARD_SLASHES_RESULT) - 10));
			END IF;
			t_temp := t_temp || '<A href="?getforwardslashes=' || urlEncode(l_record.FORWARD_SLASHES_RESULT) || t_paramsWithSort || t_baseParams || '">' || html_escape(l_record.FORWARD_SLASHES_RESULT) || '</A>';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>';
		IF coalesce(length(l_record.FORWARD_SLASHES_DUMP), 0) > 0 THEN
			t_temp := t_temp || '<A href="/ocsp-response?caID=' || l_record.CA_ID::text || '&url=' || urlEncode(l_record.URL) || '&request=getforwardslashes" target="_blank">' || length(l_record.FORWARD_SLASHES_DUMP)::text || '</A>';
		ELSE
			t_temp := t_temp || '&nbsp;';
		END IF;
		t_temp := t_temp || '</TD>
    <TD>' || coalesce((l_record.FORWARD_SLASHES_DURATION / 1000000)::text, '&nbsp;') || '</TD>
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
