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

CREATE OR REPLACE FUNCTION ocsp_response(
	caID					ocsp_responder.CA_ID%TYPE,
	url						ocsp_responder.URL%TYPE,
	request					text,
	type					text
) RETURNS text
AS $$
DECLARE
	t_caName				text;
	t_responder				ocsp_responder%ROWTYPE;
	t_output				text;
	t_dump					bytea;
	t_temp_bytes			bytea;
	t_temp					text;
	t_byte					integer;
	t_pos					integer;
	t_bodyPos				integer;
	t_fullRows				integer;
BEGIN
	SELECT ca.NAME
		INTO t_caName
		FROM ca
		WHERE ca.ID = caID;

	t_output :=
'  <SPAN class="whiteongrey">OCSP Response</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH class="outer">Request Type</TH>
    <TD class="outer">' || html_escape(
			CASE lower(request)
				WHEN 'get' THEN 'GET request'
				WHEN 'post' THEN 'POST request'
				WHEN 'getrandomserial' THEN 'GET Random Serial Number'
				WHEN 'postrandomserial' THEN 'POST Random Serial Number'
				WHEN 'randomserial' THEN 'POST Random Serial Number'
				ELSE 'Unrecognized Request Type'
			END
		) || '</TD>
  </TR>
  <TR>
    <TH class="outer">Issuer</TH>
    <TD class="outer">';
	IF t_caName IS NULL THEN
		t_output := t_output || '<I>Unknown</I>';
	ELSE
		t_output := t_output || '<A href="/?caID=' || caID::text || '">' || html_escape(t_caName) || '</A></TD>';
	END IF;
	t_output := t_output || '
  </TR>
  <TR>
    <TH class="outer">Responder URL</TH>
    <TD class="outer">' || html_escape(url) || '</TD>
  </TR>
  <TR>
    <TH class="outer">Response Summary</TH>
    <TD class="outer">';

	SELECT orp.*
		INTO t_responder
		FROM ocsp_responder orp
		WHERE orp.CA_ID = caID
			AND orp.URL = ocsp_response.url;

	IF NOT FOUND THEN
		t_output := t_output || 'Not found';
	ELSIF lower(request) = 'get' THEN
		t_output := t_output || html_escape(t_responder.GET_RESULT);
	ELSIF lower(request) = 'post' THEN
		t_output := t_output || html_escape(t_responder.POST_RESULT);
	ELSIF lower(request) = 'getrandomserial' THEN
		t_output := t_output || html_escape(t_responder.GET_RANDOM_SERIAL_RESULT);
	ELSIF lower(request) IN ('postrandomserial', 'randomserial') THEN
		t_output := t_output || html_escape(t_responder.POST_RANDOM_SERIAL_RESULT);
	ELSE
		t_output := t_output || 'Unrecognized Request Type';
	END IF;

	t_output := t_output ||
'  </TR>
  <TR>
    <TH class="outer">';
	IF lower(type) = 'dump' THEN
		t_output := t_output || 'Response';
	ELSE
		t_output := t_output || '<A href="?caID=' || caID::text || '&url=' || urlEncode(url) || '&request=' || request || '&type=dump">Response</A>';
	END IF;
	t_output := t_output || ' | ';
	IF lower(type) = 'asn1' THEN
		t_output := t_output || 'ASN.1';
	ELSE
		t_output := t_output || '<A href="?caID=' || caID::text || '&url=' || urlEncode(url) || '&request=' || request || '&type=asn1">ASN.1</A>';
	END IF;
	t_output := t_output || ' | ';
	IF lower(type) = 'text' THEN
		t_output := t_output || 'Text';
	ELSE
		t_output := t_output || '<A href="?caID=' || caID::text || '&url=' || urlEncode(url) || '&request=' || request || '&type=text">Text</A>';
	END IF;
	t_output := t_output || '</TH>
';
	IF lower(type) = 'asn1' THEN
		t_output := t_output ||
'	      <BR><BR><SPAN class="small">Powered by <A href="//lapo.it/asn1js/" target="_blank">asn1js</A><BR>';
	END IF;
	t_output := t_output ||
'    <TD class="text">';

	IF NOT FOUND THEN
		t_output := t_output || 'Not found';
	ELSIF lower(request) = 'get' THEN
		t_dump := t_responder.GET_DUMP;
	ELSIF lower(request) = 'post' THEN
		t_dump := t_responder.POST_DUMP;
	ELSIF lower(request) = 'getrandomserial' THEN
		t_dump := t_responder.GET_RANDOM_SERIAL_DUMP;
	ELSIF lower(request) IN ('postrandomserial', 'randomserial') THEN
		t_dump := t_responder.POST_RANDOM_SERIAL_DUMP;
	ELSE
		t_output := t_output || 'Unrecognized Request Type';
	END IF;

	IF length(coalesce(t_dump, '')) > 0 THEN
		t_pos := position(E'\\x0D0A0D0A' in t_dump);
		IF t_pos = 0 THEN
			t_output := t_output || 'ERROR!';
		ELSIF lower(type) = 'dump' THEN
			t_output := t_output || replace(encode(substring(t_dump from 1 for (t_pos + 3)), 'escape'), chr(13) || chr(10), '<BR>');
			t_pos := t_pos + 4;
			t_fullRows := (length(t_dump) - t_pos) >> 4;
			t_bodyPos := t_pos;
			FOR i IN 1..t_fullRows+1 LOOP
				t_temp_bytes := substring(t_dump from t_pos for 16);
				t_temp := '';
				FOR j IN 0..(length(t_temp_bytes) - 1) LOOP
					t_byte := get_byte(t_temp_bytes, j);
					IF t_byte BETWEEN 32 AND 126 THEN
						t_temp := t_temp || chr(t_byte);
					ELSE
						t_temp := t_temp || '.';
					END IF;
				END LOOP;
				t_temp := ' | ' || html_escape(t_temp) || '<BR>';
				FOR j IN length(t_temp_bytes)..15 LOOP
					t_temp := '&nbsp; &nbsp;' || t_temp;
				END LOOP;
				t_output := t_output || lpad(to_hex(t_pos - t_bodyPos), 8, '0') || ' '
							|| array_to_string(regexp_split_to_array(encode(t_temp_bytes, 'hex'), E'(?=(..)+$)'), ' ')
							|| t_temp;
				t_pos := t_pos + 16;
			END LOOP;
		ELSIF lower(type) = 'asn1' THEN
			t_output := t_output || '
      <DIV id="dump" style="position:absolute;right:20px;"></DIV>
      <DIV id="tree"></DIV>
      <SCRIPT type="text/javascript" src="/asn1js/base64.js"></SCRIPT>
      <SCRIPT type="text/javascript" src="/asn1js/oids.js"></SCRIPT>
      <SCRIPT type="text/javascript" src="/asn1js/int10.js"></SCRIPT>
      <SCRIPT type="text/javascript" src="/asn1js/asn1.js"></SCRIPT>
      <SCRIPT type="text/javascript" src="/asn1js/dom.js"></SCRIPT>
      <SCRIPT type="text/javascript">
        var tree = document.getElementById(''tree'');
        var dump = document.getElementById(''dump'');
        tree.innerHTML = '''';
        dump.innerHTML = '''';
        try {
          var asn1 = ASN1.decode(Base64.unarmor('''
			|| translate(encode(substring(t_dump from (t_pos + 4)), 'base64'), chr(10), '')
			|| '''));
          tree.appendChild(asn1.toDOM());
          dump.appendChild(asn1.toHexDOM());
        } catch (e) {
          if (''textContent'' in tree)
            tree.textContent = e;
          else
            tree.innerText = e;
        }
      </SCRIPT>
';
		ELSIF lower(type) = 'text' THEN
			t_output := t_output || replace(replace(ocspresponse_print(substring(t_dump from (t_pos + 4)), 196608 /* X509V3_EXT_DUMP_UNKNOWN */), chr(10), '<BR>'), ' ', '&nbsp;');
		END IF;
	END IF;

	RETURN t_output || '</TD>
  </TR>
</TABLE>
';
END;
$$ LANGUAGE plpgsql;

