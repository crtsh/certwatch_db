/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2016 COMODO CA Limited
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

CREATE OR REPLACE FUNCTION web_apis(
	name				text,
	paramNames			text[],
	paramValues			text[]
) RETURNS text
AS $$
DECLARE
	c_params			text[] := ARRAY[
		'd', 'Download Certificate', NULL,
		'c', 'ID', 'SHA-1(Certificate)', 'SHA-256(Certificate)', NULL,
		'id', 'ID', NULL,
		'sha1', 'SHA-1(Certificate)', NULL,
		'sha256', 'SHA-256(Certificate)', NULL,
		'asn1', 'Certificate ASN.1', NULL,
		'ctid', 'CT Entry ID', NULL,
		'ca', 'CA ID', 'CA Name', NULL,
		'caid', 'CA ID', NULL,
		'caname', 'CA Name', NULL,
		'serial', 'Serial Number', NULL,
		'spkisha1', 'SHA-1(SubjectPublicKeyInfo)', NULL,
		'subjectsha1', 'SHA-1(Subject)', NULL,
		'identity', 'Identity', NULL,
		'commonname', 'Common Name', NULL,
		'cn', 'Common Name', NULL,
		'emailaddress', 'Email Address', NULL,
		'e', 'Email Address', NULL,
		'organizationalunitname', 'Organizational Unit Name', NULL,
		'ou', 'Organizational Unit Name', NULL,
		'organizationname', 'Organization Name', NULL,
		'o', 'Organization Name', NULL,
		'dnsname', 'Domain Name', NULL,
		'domain', 'Domain Name', NULL,
		'rfc822name', 'Email Address (SAN)', NULL,
		'esan', 'Email Address (SAN)', NULL,
		'ipaddress', 'IP Address', NULL,
		'ip', 'IP Address', NULL,
		'q', 'ID', 'SHA-1(Certificate)', 'SHA-256(Certificate)', 'Identity', NULL,
		'a', 'Advanced', NULL,
		's', 'Simple', NULL
	];
	t_paramNo			integer;
	t_paramName			text;
	t_value				text;
	t_type				text			:= 'Simple';
	t_bytea				bytea;
	t_output			text;
	t_title				text;
	t_certificateID		certificate.ID%TYPE;
	t_certificateSHA1	bytea;
	t_certificateSHA256	bytea;
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_caID				ca.ID%TYPE;
	t_serialNumber		bytea;
	t_spkiSHA1			bytea;
	t_nameType			name_type;
	t_text				text;
	t_offset			integer;
	t_pos1				integer;
	t_temp				text;
	t_query				text;
	t_matchType			text			:= '=';
	t_showCABLint		boolean;
	t_useReverseIndex	boolean			:= FALSE;
	t_showIdentity		boolean;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_issuerCAID_table	text;
	t_caPublicKey		ca.PUBLIC_KEY%TYPE;
	t_count				integer;
	t_pageNo			integer;
	t_resultsPerPage	integer			:= 100;
	l_record			RECORD;
BEGIN
	FOR t_paramNo IN 1..array_length(c_params, 1) LOOP
		IF t_value IS NULL THEN
			t_paramName := c_params[t_paramNo];
			t_value := coalesce(
				btrim(get_parameter(t_paramName, paramNames, paramValues)), ''
			);
		ELSIF t_value = '' THEN
			IF c_params[t_paramNo] IS NULL THEN
				t_value := NULL;
			END IF;
		ELSE
			t_type := c_params[t_paramNo];

			BEGIN
				t_bytea := decode(translate(t_value, ':', ''), 'hex');
			EXCEPTION
				WHEN invalid_parameter_value THEN
					BEGIN
						t_bytea := decode(
							'0' || translate(t_value, ':', ''), 'hex'
						);
					EXCEPTION
						WHEN others THEN
							t_bytea := NULL;
					END;
				WHEN others THEN
					t_bytea := NULL;
			END;

			IF t_type = 'Download Certificate' THEN
				RETURN download_cert(t_value::integer);
			ELSIF t_type IN ('ID', 'Certificate ASN.1', 'CA ID', 'CT Entry ID') THEN
				EXIT WHEN btrim(t_value, '0123456789') = '';
			ELSIF t_type IN (
						'Simple', 'Advanced', 'CA Name',
						'Identity', 'Common Name', 'Email Address',
						'Organizational Unit Name', 'Organization Name',
						'Domain Name', 'Email Address (SAN)', 'IP Address'
					) THEN
				EXIT;
			ELSIF t_type IN (
						'SHA-1(Certificate)', 'SHA-1(SubjectPublicKeyInfo)',
						'SHA-1(Subject)'
					) THEN
				EXIT WHEN length(t_bytea) = 20;
			ELSIF t_type = 'SHA-256(Certificate)' THEN
				EXIT WHEN length(t_bytea) = 32;
			ELSIF t_type = 'Serial Number' THEN
				EXIT WHEN t_bytea IS NOT NULL;
			ELSE
				t_type := 'Invalid value';
				EXIT;
			END IF;
		END IF;
	END LOOP;

	IF t_type IS NULL THEN
		t_type := 'Simple';
	END IF;

	IF t_type IN ('Simple', 'Advanced') THEN
		t_title := 'COMODO';
	ELSIF t_type IN (
				'SHA-1(SubjectPublicKeyInfo)',
				'SHA-1(Subject)',
				'SHA-1(Certificate)',
				'SHA-256(Certificate)'
			) THEN
		t_value := encode(t_bytea, 'hex');
	ELSIF t_type = 'CT Entry ID' THEN
		t_title := 'CT:' || t_value;
	ELSIF t_type IN ('CA ID', 'CA Name') THEN
		t_title := 'CA:' || t_value;
	ELSIF t_type = 'Serial Number' THEN
		t_value := encode(t_bytea, 'hex');
		t_title := 'Serial#' || t_value;
	ELSIF t_type = 'Identity' THEN
		t_nameType := NULL;
	ELSIF t_type = 'Common Name' THEN
		t_nameType := 'commonName';
	ELSIF t_type = 'Email Address' THEN
		t_nameType := 'emailAddress';
	ELSIF t_type = 'Organizational Unit Name' THEN
		t_nameType := 'organizationalUnitName';
	ELSIF t_type = 'Organization Name' THEN
		t_nameType := 'organizationName';
	ELSIF t_type = 'Domain Name' THEN
		t_nameType := 'dNSName';
	ELSIF t_type = 'Email Address (SAN)' THEN
		t_nameType := 'rfc822Name';
	ELSIF t_type = 'IP Address' THEN
		t_nameType := 'iPAddress';
	END IF;

	IF t_title IS NULL THEN
		t_title := coalesce(t_value, '');
	END IF;

	-- Generate page header.
	t_output :=
'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <LINK rel="canonical" href="https://crt.sh/">
  <TITLE>crt.sh | ' || html_escape(t_title) || '</TITLE>
  <META name="description" content="Free CT Log Certificate Search Tool from COMODO">
  <META name="keywords" content="crt.sh, CT, Certificate Transparency, Certificate Search, SSL Certificate, Comodo CA">
';
	IF t_type = 'Certificate ASN.1' THEN
		t_output := t_output ||
'<LINK rel="stylesheet" href="/asn1js/index.css" type="text/css">
';
	END IF;
	t_output := t_output ||
'  <STYLE type="text/css">
    a {
      white-space: nowrap;
    }
    body {
      color: #888888;
      font: 12pt Arial, sans-serif;
      padding-top: 10px;
      text-align: center;
    }
    form {
      margin: 0px;
    }
    span.title {
      border: 1px solid;
      color: #BF2E1A;
      font: bold 18pt Arial, sans-serif;
      padding: 0px 5px;
    }
    span.text {
      color: #888888;
      font: 10pt Arial, sans-serif;
    }
    span.whiteongrey {
      background-color: #CCCCCC;
      border: 1px solid;
      color: #FFFFFF;
      font: bold 18pt Arial, sans-serif;
      padding: 0px 5px;
    }
    span.error {
      background-color: #FFDFDF;
      color: #CC0000;
      font-weight: bold;
    }
    span.fatal {
      background-color: #0000AA;
      color: #FFFFFF;
      font-weight: bold;
    }
    span.warning {
      background-color: #FFEFDF;
      color: #DF6000;
    }
    table {
      border-collapse: collapse;
      border: 1px solid #888888;
      color: #222222;
      font: 10pt Arial, sans-serif;
      margin-left: auto;
      margin-right: auto;
    }
    table.options {
      border: none;
      margin-left: 10px;
    }
    td, th {
      border: 1px solid #DDDDDD;
      padding: 0px 2px;
      text-align: left;
      vertical-align: top;
    }
    td.outer, th.outer {
      border: 1px solid #DDDDDD;
      padding: 2px 20px;
      text-align: left;
    }
    th.heading {
      color: #888888;
      font: bold italic 12pt Arial;
      padding: 20px 0px 0px;
      text-align: center;
    }
    th.options, td.options {
      border: none;
      vertical-align: middle;
    }
    td.text {
      font: 10pt Courier New, sans-serif;
      padding: 2px 20px;
    }
    .button {
      background-color: #BF2E1A;
      color: #FFFFFF;
      font: 13pt Arial;
    }
    .copyright {
      font: 8pt Arial;
      color: #DF4F3C;
    }
    .input {
      border: 1px solid #888888;
      font-weight: bold;
      text-align: center;
    }
    .small {
      font: 8pt Arial;
      color: #888888;
    }
  </STYLE>
</HEAD>
<BODY>
  <A href="?"><SPAN class="title">crt.sh</SPAN></A>';

	IF t_type = 'Invalid value' THEN
		RAISE no_data_found USING MESSAGE = t_type || ': ''' || html_escape(t_value) || '''';

	ELSIF t_type = 'Simple' THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
  <BR><BR><BR><BR>
  Enter an <B>Identity</B> (Domain Name, Organization Name, etc),
  <BR>a <B>Certificate Fingerprint</B> (SHA-1 or SHA-256) or a <B>crt.sh ID</B>:
  <BR><SPAN class="small">(% = wildcard)</SPAN>
  <BR><BR>
  <FORM name="search_form" method="GET" onsubmit="return (this.q.value != '')">
    <INPUT type="text" class="input" name="q" size="64" maxlength="255">
    <BR><BR><BR>
    <INPUT type="submit" class="button" value="Search">
    <SPAN style="position:absolute">
      &nbsp; &nbsp; &nbsp;
      <A style="font-size:8pt;vertical-align:sub" href="?a=1">Advanced...</A>
    </SPAN>
  </FORM>
  <SCRIPT type="text/javascript">
    document.search_form.q.focus();
  </SCRIPT>';

	ELSIF t_type = 'Advanced' THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
  <BR><BR><BR><BR>
  <SCRIPT type="text/javascript">
    function doSearch(
      type,
      value
    )
    {
      if ((!type) || (!value))
        return;
      var t_url = "?" + encodeURIComponent(type) + "=" + encodeURIComponent(value);
      window.location = t_url;
    }
  </SCRIPT>
  <FORM name="search_form" method="GET" onsubmit="return false">
    Enter search term:
    <BR><SPAN class="small">(% = wildcard)</SPAN>
    <BR><BR>
    <INPUT type="text" class="input" name="q" size="64" maxlength="255">
    <BR><BR><BR>
    Select search type:
    <BR><BR>
    <SELECT name="searchtype" size="18">
      <OPTION value="c" selected>CERTIFICATE</OPTION>
      <OPTION value="ID">&nbsp; crt.sh ID</OPTION>
      <OPTION value="ctid">&nbsp; CT Entry ID</OPTION>
      <OPTION value="serial">&nbsp; Serial Number</OPTION>
      <OPTION value="spkisha1">&nbsp; SHA-1(SubjectPublicKeyInfo)</OPTION>
      <OPTION value="subjectsha1">&nbsp; SHA-1(Subject)</OPTION>
      <OPTION value="sha1">&nbsp; SHA-1(Certificate)</OPTION>
      <OPTION value="sha256">&nbsp; SHA-256(Certificate)</OPTION>
      <OPTION value="ca">CA</OPTION>
      <OPTION value="CAID">&nbsp; ID</OPTION>
      <OPTION value="CAName">&nbsp; Name</OPTION>
      <OPTION value="Identity">IDENTITY</OPTION>
      <OPTION value="CN">&nbsp; commonName (Subject)</OPTION>
      <OPTION value="E">&nbsp; emailAddress (Subject)</OPTION>
      <OPTION value="OU">&nbsp; organizationalUnitName (Subject)</OPTION>
      <OPTION value="O">&nbsp; organizationName (Subject)</OPTION>
      <OPTION value="dNSName">&nbsp; dNSName (SAN)</OPTION>
      <OPTION value="rfc822Name">&nbsp; rfc822Name (SAN)</OPTION>
      <OPTION value="iPAddress">&nbsp; iPAddress (SAN)</OPTION>
    </SELECT>
    <BR><BR><BR>
    <INPUT type="submit" class="button" value="Search"
           onClick="doSearch(document.search_form.searchtype.value,document.search_form.q.value)">
    <SPAN style="position:absolute">
      &nbsp; &nbsp; &nbsp;
      <A style="font-size:8pt;vertical-align:sub" href="?">Simple...</A>
    </SPAN>
  </FORM>
  <SCRIPT type="text/javascript">
    document.search_form.q.focus();
  </SCRIPT>
  <BR><BR>CT Logs monitored:
  <BR>
  <TABLE>
    <TR>
      <TH>Name</TH>
      <TH>Operator</TH>
      <TH>URL</TH>
      <TH>Latest Entry #</TH>
      <TH>Latest STH</TH>
      <TH>MMD (hrs)</TH>
      <TH>Last Contacted</TH>
      <TH>In Chrome?</TH>
    </TR>';
		FOR l_record IN (
					SELECT ctl.NAME, ctl.OPERATOR, ctl.URL,
							ctl.LATEST_ENTRY_ID, ctl.LATEST_UPDATE,
							ctl.LATEST_STH_TIMESTAMP, ctl.MMD_IN_SECONDS,
							CASE WHEN ctl.LATEST_STH_TIMESTAMP + (ctl.MMD_IN_SECONDS || ' seconds')::interval < statement_timestamp()
								THEN ' style="color:#FF0000"'
								ELSE ''
							END FONT_STYLE,
							ctl.INCLUDED_IN_CHROME, ctl.CHROME_ISSUE_NUMBER
						FROM ct_log ctl
						WHERE ctl.IS_ACTIVE = 't'
						ORDER BY ctl.LATEST_ENTRY_ID DESC
				) LOOP
			t_output := t_output || '
    <TR>
      <TD' || l_record.FONT_STYLE || '>' || l_record.NAME || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.OPERATOR || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.URL || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.LATEST_ENTRY_ID::text || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || to_char(l_record.LATEST_STH_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce((l_record.MMD_IN_SECONDS / 60 / 60)::text, '?') || '</TD>
      <TD>' || to_char(l_record.LATEST_UPDATE, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD>
';
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '<A href="https://code.google.com/p/chromium/issues/detail?id='
									|| l_record.CHROME_ISSUE_NUMBER::text || '" target="_blank">';
				IF l_record.INCLUDED_IN_CHROME IS NOT NULL THEN
					t_output := t_output || 'M' || l_record.INCLUDED_IN_CHROME::text;
				ELSE
					t_output := t_output || 'Pending';
				END IF;
				t_output := t_output || '</A>' || chr(10);
			END IF;
			t_output := t_output ||
'    </TR>';
		END LOOP;
		t_output := t_output || '
</TABLE>';

	ELSIF t_type IN (
				'ID',
				'SHA-1(Certificate)',
				'SHA-256(Certificate)',
				'Certificate ASN.1'
			) THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
<BR><BR>
';

		-- Search for a specific Certificate.
		IF t_type IN ('ID', 'Certificate ASN.1') THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha1'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA1,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac ON (c.ID = cac.CERTIFICATE_ID)
				WHERE c.ID = t_value::integer;
		ELSIF t_type = 'SHA-1(Certificate)' THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha1'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA1,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac
									ON (c.ID = cac.CERTIFICATE_ID)
				WHERE digest(c.CERTIFICATE, 'sha1') = t_bytea;
		ELSIF t_type = 'SHA-256(Certificate)' THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha1'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA1,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac
									ON (c.ID = cac.CERTIFICATE_ID)
				WHERE digest(c.CERTIFICATE, 'sha256') = t_bytea;
		END IF;
		IF t_text IS NULL THEN
			RAISE no_data_found USING MESSAGE = 'Certificate not found ';
		END IF;

		-- For embedded SCTs, insert the Log Names.
		t_offset := 1;
		LOOP
			t_pos1 := strpos(substr(t_text, t_offset), 'Log ID    : ');
			EXIT WHEN t_pos1 = 0;
			t_pos1 := t_pos1 + t_offset - 1;
			t_temp := translate(
				substr(t_text, t_pos1 + 12, 128), ': ' || chr(10), ''
			);
			SELECT ctl.NAME
				INTO t_temp
				FROM ct_log ctl
				WHERE digest(ctl.PUBLIC_KEY, 'sha256') = decode(t_temp, 'hex');
			t_temp := 'Log Name  : ' || coalesce(html_escape(t_temp), 'Unknown')
						|| chr(10) || '                    ';
			t_text := substr(t_text, 1, t_pos1 - 1) || t_temp
						|| substr(t_text, t_pos1);
			t_offset := t_pos1 + length(t_temp) + 1;
		END LOOP;

		t_text := replace(html_escape(t_text), chr(10), '<BR>');
		t_text := replace(t_text, ', DNS:', '<BR>                DNS:');
		t_text := replace(t_text, ', IP Address:', '<BR>                IP Address:');
		t_text := replace(t_text, ' ', '&nbsp;');
		t_text := replace(
			t_text, 'Certificate:<BR>&nbsp;&nbsp;&nbsp;&nbsp;',
			'<A href="?d=' || t_certificateID::text
					|| '">Certificate:</A><BR>&nbsp;&nbsp;&nbsp;&nbsp;'
		);
		t_text := replace(
			t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Serial&nbsp;Number:',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?serial='
						|| encode(t_serialNumber, 'hex')
						|| '">Serial&nbsp;Number:</A>'
		);
		IF t_issuerCAID IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Issuer:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?caid='
						|| t_issuerCAID::text
						|| '">Issuer:</A><BR>'
			);
		END IF;
		IF t_caID IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subject:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?caid='
						|| t_caID::text
						|| '">Subject:</A><BR>'
			);
		END IF;
		t_text := replace(
			t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subject&nbsp;Public&nbsp;Key&nbsp;Info:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?spkisha1='
						|| encode(t_spkiSHA1, 'hex')
						|| '">Subject&nbsp;Public&nbsp;Key&nbsp;Info:</A><BR>'
		);

		t_offset := strpos(t_text, 'CT&nbsp;Precertificate');
		IF t_offset != 0 THEN
			SELECT c.ID::text
				INTO t_temp
				FROM certificate c
				WHERE x509_serialNumber(c.certificate) = t_serialNumber
					AND c.ISSUER_CA_ID = t_issuerCAID
					AND c.ID != t_certificateID;
			IF t_temp IS NOT NULL THEN
				IF substr(t_text, t_offset, 34) = 'CT&nbsp;Precertificate&nbsp;Poison' THEN
					t_text := substr(t_text, 1, t_offset - 1)
								|| 'CT Pre<A href="?id=' || t_temp
										|| '">certificate</A>'
								|| substr(t_text, t_offset + 22);
				ELSE
					t_text := substr(t_text, 1, t_offset - 1)
								|| 'CT <A href="?id=' || t_temp
										|| '">Precertificate</A>'
								|| substr(t_text, t_offset + 22);
				END IF;
			END IF;
		END IF;

		t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Criteria</TH>
    <TD class="outer">' || html_escape(t_type) || ' = ''' || html_escape(t_value) || '''</TD>
  </TR>
</TABLE>
<BR>
<TABLE>
  <TR>
    <TH class="outer">crt.sh ID</TH>
    <TD class="outer">' || coalesce(t_certificateID::text, '<I>Not found</I>') || '</TD>
  </TR>
  <TR>
    <TH class="outer">Certificate<BR>Transparency</TH>
    <TD class="outer">
';

		t_temp := '';
		FOR l_record IN (
					SELECT ctl.NAME, ctl.URL, ctl.OPERATOR, ctle.ENTRY_ID, ctle.ENTRY_TIMESTAMP
						FROM ct_log_entry ctle, ct_log ctl
						WHERE ctle.CERTIFICATE_ID = t_certificateID
							AND ctle.CT_LOG_ID = ctl.ID
						ORDER BY ctle.ENTRY_TIMESTAMP
				) LOOP
			t_temp := t_temp ||
'  <TR>
    <TD>' || to_char(l_record.ENTRY_TIMESTAMP, 'YYYY-MM-DD')
						|| '<BR><FONT class="small">'
						|| to_char(l_record.ENTRY_TIMESTAMP, 'HH24:MI:SS GMT')
						|| '</FONT></TD>
    <TD>' || l_record.ENTRY_ID::text || '</TD>
    <TD>' || html_escape(l_record.NAME) || '</TD>
    <TD>' || html_escape(l_record.OPERATOR) || '</TD>
    <TD>' || html_escape(l_record.URL) || '</TD>
  </TR>
';
		END LOOP;
		IF t_temp != '' THEN
			t_output := t_output ||
'<TABLE class="options" style="margin-left:0px">
  <TR>
    <TH>Timestamp</TH>
    <TH>Entry #</TH>
    <TH>Log</TH>
    <TH>Operator</TH>
    <TH>URL</TH>
  </TR>
' || t_temp ||
'</TABLE>
';
		ELSE
			t_output := t_output ||
'      No log entries found
';
		END IF;

		t_output := t_output ||
'    </TD>
  </TR>
  <TR>
    <TH class="outer">SHA-256(Certificate)</TH>
    <TD class="outer">' || coalesce(upper(encode(t_certificateSHA256, 'hex')), '<I>Not found</I>') || '</TD>
  </TR>
  <TR>
    <TH class="outer">SHA-1(Certificate)</TH>
    <TD class="outer">' || coalesce(upper(encode(t_certificateSHA1, 'hex')), '<I>Not found</I>') || '</TD>
  </TR>
';

		t_showCABLint := (',' || coalesce(get_parameter('opt', paramNames, paramValues), '') || ',') LIKE '%,cablint,%';
		IF t_showCABLint THEN
			t_output := t_output ||
'  <TR>
    <TH class="outer">CA/B Forum lint
      <BR><BR><SPAN class="small">Powered by <A href="//github.com/awslabs/certlint" target="_blank">certlint</A></SPAN>
    </TH>
    <TD class="text">
';
			FOR l_record IN (
						SELECT replace(substr(CABLINT, 4), CHR(9) || 'stdin', '') ISSUE_TEXT,
								CASE substr(CABLINT, 1, 2)
									WHEN 'I:' THEN 1
									WHEN 'F:' THEN 2
									WHEN 'E:' THEN 3
									WHEN 'W:' THEN 4
									ELSE 5
								END ISSUE_TYPE,
								CASE substr(CABLINT, 1, 2)
									WHEN 'I:' THEN '<SPAN>&nbsp; &nbsp; INFO:'
									WHEN 'F:' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
									WHEN 'E:' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
									WHEN 'W:' THEN '<SPAN class="warning">&nbsp;WARNING:'
									ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || substr(CABLINT, 1, 2)
								END ISSUE_HEADING
							FROM unnest(string_to_array(cablint(t_certificate), CHR(10))) CABLINT
							ORDER BY ISSUE_TYPE, ISSUE_TEXT
					) LOOP
				t_output := t_output ||
'      ' || l_record.ISSUE_HEADING || ' ' || l_record.ISSUE_TEXT || '&nbsp;</SPAN><BR>';
			END LOOP;
			t_output := t_output ||
'    </TD>
  </TR>
';
		END IF;

		t_output := t_output ||
'  <TR>
';

		IF t_type = 'Certificate ASN.1' THEN
			t_output := t_output ||
'    <TH class="outer"><A href="?id=' || t_certificateID::text || '">Certificate</A> | ASN.1
      <BR><BR><SPAN class="small">Powered by <A href="//lapo.it/asn1js/" target="_blank">asn1js</A>
';
			IF NOT t_showCABLint THEN
				t_output := t_output ||
'      <BR><BR><A href="?asn1=' || t_certificateID::text || '&opt=cablint">Run cablint</A>
';
			END IF;
			t_output := t_output ||
'      </SPAN>
    </TH>
    <TD class="text">
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
			|| translate(encode(t_certificate, 'base64'), chr(10), '')
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
		ELSE
			t_output := t_output ||
'    <TH class="outer">Certificate | <A href="?asn1=' || t_certificateID::text || '">ASN.1</A>
';
			IF NOT t_showCABLint THEN
				t_output := t_output ||
'      <BR><BR><A href="?id=' || t_certificateID::text || '&opt=cablint">Run cablint</A>
';
			END IF;
			t_output := t_output ||
'      </SPAN>
    </TH>
    <TD class="text">' || coalesce(t_text, '<I>Not found</I>');
		END IF;
		t_output := t_output ||
'    </TD>
  </TR>
</TABLE>
';

	ELSIF t_type IN ('CA ID', 'CA Name') THEN
		t_output := t_output || ' <SPAN class="whiteongrey">CA Search</SPAN>
<BR><BR>
';

		-- Determine whether to use a reverse index (if available).
		IF position('%' IN t_value) != 0 THEN
			t_matchType := 'LIKE';
			t_useReverseIndex := (
				position('%' IN t_value) < position('%' IN reverse(t_value))
			);
		END IF;

		t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Criteria</TH>
    <TD class="outer">' || html_escape(t_type)
						|| ' ' || html_escape(t_matchType)
						|| ' ''' || html_escape(t_value) || '''</TD>
  </TR>
</TABLE>
<BR>
';

		-- Search for a specific CA.
		IF t_type = 'CA ID' THEN
			SELECT ca.ID, html_escape(ca.NAME), ca.PUBLIC_KEY
				INTO t_caID, t_text, t_caPublicKey
				FROM ca
				WHERE ca.ID = t_value::integer;
			IF t_text IS NULL THEN
				RAISE no_data_found USING MESSAGE = 'CA not found';
			END IF;

			SELECT min(cac.CERTIFICATE_ID)
				INTO t_certificateID
				FROM ca_certificate cac
				WHERE cac.CA_ID = t_caID;
			IF t_certificateID IS NOT NULL THEN
				SELECT html_escape(x509_print(c.CERTIFICATE, NULL, 7999))
					INTO t_text
					FROM certificate c
					WHERE c.ID = t_certificateID;
				t_text := replace(t_text, '        Subject:', 'Subject:');
				t_text := replace(t_text, chr(10) || '        ', '<BR>');
				t_text := replace(t_text, ' ', '&nbsp;');
			END IF;

			t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">crt.sh CA ID</TH>
    <TD class="outer">' || t_caID::text || '</TD>
  </TR>
  <TR>
    <TH class="outer">CA Name/Key</TH>
    <TD class="text">' || t_text || '</TD>
  </TR>
  <TR>
    <TH class="outer">Certificates</TH>
    <TD class="outer">
<TABLE class="options" style="margin-left:0px">
  <TR>
    <TH style="white-space:nowrap">Not Before</TH>
    <TH style="white-space:nowrap">Not After</TH>
    <TH>Issuer Name</TH>
  </TR>
';
			FOR l_record IN (
						SELECT x509_issuerName(c.CERTIFICATE)	ISSUER_NAME,
								c.ID,
								x509_notBefore(c.CERTIFICATE)	NOT_BEFORE,
								x509_notAfter(c.CERTIFICATE)	NOT_AFTER
							FROM ca_certificate cac, certificate c
								LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
							WHERE cac.CA_ID = t_caID
								AND cac.CERTIFICATE_ID = c.ID
							ORDER BY ISSUER_NAME, NOT_BEFORE
					) LOOP
				t_output := t_output ||
'  <TR>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || '</TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_AFTER, 'YYYY-MM-DD') || '</TD>
    <TD><A href="?id=' || l_record.ID || '">'
						|| html_escape(l_record.ISSUER_NAME) || '</A></TD>
  </TR>
';
			END LOOP;

			t_output := t_output ||
'</TABLE>
    </TD>
  </TR>
  <TR><TD colspan=2>&nbsp;</TD></TR>
  <TR>
    <TH class="outer">Issued Certificates</TH>
    <TD class="outer">
      <SCRIPT type="text/javascript">
        function identitySearch(
          type,
          value
        )
        {
          if ((!type) || (!value))
            return;
          var t_url = "?" + encodeURIComponent(type) + "=" + encodeURIComponent(value);
          if (document.search_form.caID.value != "")
            t_url = t_url + "&iCAID=" + document.search_form.caID.value;
          window.location = t_url;
        }
      </SCRIPT>
      <FORM name="search_form" method="GET" onSubmit="return false">
        <INPUT type="hidden" name="caID" value="' || t_caID::text || '">
        <TABLE class="options" style="margin-left:0px">
          <TR>
            <TD class="options">
              <SPAN class="text">Select search type:</SPAN>
              <BR><SELECT name="idtype" size="8">
                <OPTION value="Identity" selected>IDENTITY</OPTION>
                <OPTION value="CN">&nbsp; commonName (Subject)</OPTION>
                <OPTION value="E">&nbsp; emailAddress (Subject)</OPTION>
                <OPTION value="OU">&nbsp; organizationalUnitName (Subject)</OPTION>
                <OPTION value="O">&nbsp; organizationName (Subject)</OPTION>
                <OPTION value="dNSName">&nbsp; dNSName (SAN)</OPTION>
                <OPTION value="rfc822Name">&nbsp; rfc822Name (SAN)</OPTION>
                <OPTION value="iPAddress">&nbsp; iPAddress (SAN)</OPTION>
              </SELECT>
            </TD>
            <TD class="options" style="padding-left:20px;vertical-align:top">
              <SPAN class="text">Enter search term:</SPAN><BR><SPAN class="small">(% = wildcard)</SPAN>
              <BR><BR>
              <INPUT type="text" name="idvalue" class="input" size="25" style="margin-top:2px">
              <BR><BR><BR>
              <INPUT type="submit" class="button" value="Search"
                     onClick="identitySearch(document.search_form.idtype.value,document.search_form.idvalue.value)">
            </TD>
          </TR>
        </TABLE>
      </FORM>
      <SCRIPT type="text/javascript">
        document.search_form.idvalue.focus();
      </SCRIPT>
    </TD>
  </TR>
  <TR><TD colspan=2>&nbsp;</TD></TR>
  <TR>
    <TH class="outer">Parent CAs</TH>
    <TD class="outer">
';
			t_text := NULL;
			FOR l_record IN (
						SELECT x509_issuerName(c.CERTIFICATE)	ISSUER_NAME,
								c.ISSUER_CA_ID
							FROM ca_certificate cac, certificate c
								LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
							WHERE cac.CA_ID = t_caID
								AND cac.CERTIFICATE_ID = c.ID
								AND c.ISSUER_CA_ID != t_caID
							GROUP BY x509_issuerName(c.CERTIFICATE),
									c.ISSUER_CA_ID
							ORDER BY x509_issuerName(c.CERTIFICATE)
					) LOOP
				IF t_text IS NULL THEN
					t_text := '
<TABLE class="options" style="margin-left:0px">
';
				END IF;
				t_text := t_text ||
'  <TR>
    <TD>';
				IF l_record.ISSUER_CA_ID IS NULL THEN
					t_text := t_text || html_escape(l_record.ISSUER_NAME);
				ELSE
					t_text := t_text || '<A href="?caid=' || l_record.ISSUER_CA_ID::text || '">'
									|| html_escape(l_record.ISSUER_NAME) || '</A>';
				END IF;
				t_text := t_text || '</TD>
  </TR>
';
			END LOOP;
			IF t_text IS NOT NULL THEN
				t_text := t_text ||
'</TABLE>
';
			END IF;
			t_output := t_output || coalesce(t_text, '<I>None found</I>') ||
'    </TD>
  </TR>
  <TR>
    <TH class="outer">Child CAs</TH>
    <TD class="outer">
';
			t_text := NULL;
			FOR l_record IN (
						SELECT x509_subjectName(c.CERTIFICATE)	SUBJECT_NAME,
								cac.CA_ID
							FROM certificate c, ca_certificate cac
								LEFT OUTER JOIN ca ON (cac.CA_ID = ca.ID)
							WHERE x509_canIssueCerts(c.CERTIFICATE)
								AND c.ISSUER_CA_ID = t_caID
								AND c.ID = cac.CERTIFICATE_ID
								AND cac.CA_ID != t_caID
							GROUP BY x509_subjectName(c.CERTIFICATE),
									cac.CA_ID
							ORDER BY x509_subjectName(c.CERTIFICATE)
					) LOOP
				IF t_text IS NULL THEN
					t_text := '
<TABLE class="options" style="margin-left:0px">
';
				END IF;
				t_text := t_text ||
'  <TR>
    <TD>';
				IF l_record.CA_ID IS NULL THEN
					t_text := t_text || html_escape(l_record.SUBJECT_NAME);
				ELSE
					t_text := t_text || '<A href="?caid=' || l_record.CA_ID::text || '">'
									|| html_escape(l_record.SUBJECT_NAME) || '</A>';
				END IF;
				t_text := t_text || '</TD>
  </TR>
';
			END LOOP;
			IF t_text IS NOT NULL THEN
				t_text := t_text ||
'</TABLE>
';
			END IF;
			t_output := t_output || coalesce(t_text, '<I>None found</I>') ||
'    </TD>
  </TR>
';
			t_output := t_output ||
'</TABLE>
';
		-- Search for (potentially) multiple CAs.
		ELSE	/* CA Name */
			t_query := 'SELECT ca.ID, ca.NAME' || chr(10) ||
						'	FROM ca' || chr(10);
			IF t_useReverseIndex THEN
				t_query := t_query ||
						'	WHERE reverse(lower(ca.NAME)) LIKE reverse(lower($1))' || chr(10);
			ELSE
				t_query := t_query ||
						'	WHERE lower(ca.NAME) LIKE lower($1)' || chr(10);
			END IF;

			t_query := t_query ||
						'	ORDER BY ca.NAME';
			FOR l_record IN EXECUTE t_query
							USING t_value LOOP
				IF t_text IS NULL THEN
					t_text := '
<TABLE class="options" style="margin-left:0px">
';
				END IF;
				t_text := t_text ||
'  <TR>
    <TD>' || '<A href="?caid=' || l_record.ID::text || '">'
							|| html_escape(l_record.NAME) || '</A></TD>
  </TR>
';
			END LOOP;
			IF t_text IS NOT NULL THEN
				t_text := t_text ||
'</TABLE>
';
			END IF;

			t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">CAs</TH>
    <TD class="outer">' || coalesce(t_text, '<I>None found</I>') || '</TD>
  </TR>
</TABLE>
';
		END IF;

	ELSIF t_type IN (
				'CT Entry ID',
				'Serial Number',
				'SHA-1(SubjectPublicKeyInfo)',
				'SHA-1(Subject)',
				'Identity',
				'Common Name',
				'Email Address',
				'Organizational Unit Name',
				'Organization Name',
				'Domain Name',
				'Email Address (SAN)',
				'IP Address'
			) THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Identity Search</SPAN>
<BR><BR>
';

		-- Determine whether to use a reverse index (if available).
		IF position('%' IN t_value) != 0 THEN
			t_matchType := 'LIKE';
			t_useReverseIndex := (
				position('%' IN t_value) < position('%' IN reverse(t_value))
			);
		END IF;

		t_caID := get_parameter('icaid', paramNames, paramValues)::integer;
		t_temp := coalesce(get_parameter('p', paramNames, paramValues), '');
		IF t_temp = '' THEN
			IF (t_value = '%') AND (t_caID IS NOT NULL) THEN
				t_pageNo := 1;
			END IF;
		ELSIF lower(t_temp) = 'off' THEN
			NULL;
		ELSIF t_temp IS NOT NULL THEN
			t_pageNo := t_temp::integer;
			IF t_pageNo < 1 THEN
				t_pageNo := 1;
			END IF;
		END IF;
		t_resultsPerPage := coalesce(get_parameter('n', paramNames, paramValues)::integer, 100);

		t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Criteria</TH>
    <TD class="outer">' || html_escape(t_type)
						|| ' ' || html_escape(t_matchType)
						|| ' ''' || html_escape(t_value) || '''';
		IF t_caID IS NOT NULL THEN
			t_output := t_output || '; Issuer CA ID = ' || t_caID::text;
		END IF;
		t_output := t_output || '</TD>
  </TR>
</TABLE>
<BR>
';

		-- Search for (potentially) multiple certificates.
		IF t_caID IS NOT NULL THEN
			-- Show all of the certs for 1 identity issued by 1 CA.
			t_query := 'SELECT c.ID, x509_subjectName(c.CERTIFICATE) SUBJECT_NAME,' || chr(10) ||
						'		x509_notBefore(c.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
						'		x509_notAfter(c.CERTIFICATE) NOT_AFTER' || chr(10) ||
						'	FROM certificate c' || chr(10);
			IF t_type IN ('Serial Number', 'SHA-1(SubjectPublicKeyInfo)', 'SHA-1(Subject)') THEN
				IF t_type = 'Serial Number' THEN
					t_query := t_query ||
						'	WHERE x509_serialNumber(c.CERTIFICATE) = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
					t_query := t_query ||
						'	WHERE digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(Subject)' THEN
					t_query := t_query ||
						'	WHERE digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				END IF;
				t_query := t_query ||
						'		AND c.ISSUER_CA_ID = $1' || chr(10);
			ELSIF (t_type = 'Identity') AND (t_value = '%') THEN
				t_query := t_query ||
						'	WHERE c.ISSUER_CA_ID = $1' || chr(10);
			ELSE
				t_query := t_query ||
						'	WHERE c.ID IN (' || chr(10) ||
						'		SELECT DISTINCT ci.CERTIFICATE_ID' || chr(10) ||
						'			FROM certificate_identity ci' || chr(10) ||
						'			WHERE ci.ISSUER_CA_ID = $1' || chr(10);
				IF t_useReverseIndex THEN
					t_query := t_query ||
						'				AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($2))' || chr(10);
				ELSE
					t_query := t_query ||
						'				AND lower(ci.NAME_VALUE) LIKE lower($2)' || chr(10);
				END IF;

				IF t_type != 'Identity' THEN
					t_query := t_query || ' ' ||
						'				AND ci.NAME_TYPE = ' || quote_literal(t_nameType) || chr(10);
				END IF;
				t_query := t_query ||
						'	)' || chr(10);
			END IF;
			t_query := t_query ||
						'	ORDER BY NOT_BEFORE DESC';
			IF t_pageNo IS NOT NULL THEN
				t_query := t_query || chr(10) ||
						'	OFFSET ' || ((t_pageNo - 1) * t_resultsPerPage)::text || chr(10) ||
						'	LIMIT ' || t_resultsPerPage::text;
			END IF;

			t_text := '';

			t_count := 0;
			FOR l_record IN EXECUTE t_query
							USING t_caID, t_value LOOP
				t_count := t_count + 1;
				t_text := t_text ||
'  <TR>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || '</TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_AFTER, 'YYYY-MM-DD') || '</TD>
    <TD><A href="?id=' || l_record.ID::text || '">'
					|| html_escape(l_record.SUBJECT_NAME) || '</A></TD>
  </TR>
';
			END LOOP;

			IF t_pageNo IS NOT NULL THEN
				t_temp := 'SELECT count(*)' || chr(10) || substring(t_query from '	FROM.*	ORDER BY');
				t_temp := substr(t_temp, 1, length(t_temp) - length('	ORDER BY'));
				EXECUTE t_temp INTO t_count USING t_caID, t_value;
			END IF;

			SELECT ca.NAME
				INTO t_temp
				FROM ca
				WHERE ca.ID = t_caID;
			t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Issuer Name</TH>
    <TD class="outer"><A href="?caid=' || t_caID::text || '">'
									|| coalesce(html_escape(t_temp), '&nbsp;') || '</A></TD>
  </TR>
  <TR>
    <TH class="outer">Certificates<BR>(' || trim(to_char(t_count, '999G999G999G999G999')) || ')</TH>
    <TD class="outer">';
			IF t_text != '' THEN
				t_output := t_output || '
<TABLE>
';
				IF (t_pageNo IS NOT NULL) AND (t_count > t_resultsPerPage) THEN
					t_output := t_output ||
'  <TR><TD colspan="3" style="text-align:center;padding:4px">';
					IF t_pageNo > 1 THEN
						t_output := t_output || '<A style="font-size:8pt" href="?' ||
									urlEncode(t_type) || '=' || urlEncode(t_value) ||
									'&iCAID=' || t_caID::text ||
									'&p=' || (t_pageNo - 1)::text ||
									'&n=' || t_resultsPerPage::text || '">Previous</A> &nbsp; ';
					END IF;
					t_output := t_output || '<B>' ||
								(((t_pageNo - 1) * t_resultsPerPage) + 1)::integer || '</B> to <B>' ||
								least(t_pageNo * t_resultsPerPage, t_count)::integer || '</B>';
					IF (t_pageNo * t_resultsPerPage) < t_count THEN
						t_output := t_output || ' &nbsp; <A style="font-size:8pt" href="?' ||
									urlEncode(t_type) || '=' || urlEncode(t_value) ||
									'&iCAID=' || t_caID::text ||
									'&p=' || (t_pageNo + 1)::text ||
									'&n=' || t_resultsPerPage::text || '">Next</A>';
					END IF;
					t_output := t_output || '</TD></TR>
';
				END IF;
				t_output := t_output ||
'  <TR>
    <TH style="white-space:nowrap">Not Before</TH>
    <TH style="white-space:nowrap">Not After</TH>
    <TH>Subject Name</TH>
  </TR>
' || t_text ||
'</TABLE>
';
			ELSE
				t_output := t_output ||
'<I>None found</I>';
			END IF;
			t_output := t_output || '</TD>
  </TR>
</TABLE>
';
		ELSE
			IF trim(t_value, '%') = '' THEN
				RAISE no_data_found
						USING MESSAGE = '</SPAN>
<BR><BR>Value not permitted: ''%''';
			END IF;

			-- Group certs for the same identity issued by the same CA.
			IF t_type = 'CT Entry ID' THEN
				t_issuerCAID_table := 'c';
				t_query := 'SELECT c.ISSUER_CA_ID, ca.NAME,' || chr(10) ||
							'		ctl.NAME NAME_VALUE,' || chr(10) ||
							'		min(c.ID) MIN_CERT_ID,' || chr(10) ||
							'		count(DISTINCT c.ID) NUM_CERTS' || chr(10) ||
							'	FROM ct_log_entry ctle, ct_log ctl, certificate c';
			ELSIF t_type = 'Serial Number' THEN
				t_issuerCAID_table := 'c';
				t_query := 'SELECT c.ISSUER_CA_ID, ca.NAME,' || chr(10) ||
							'		encode(x509_serialNumber(c.CERTIFICATE), ''hex'') NAME_VALUE,' || chr(10) ||
							'		min(c.ID) MIN_CERT_ID,' || chr(10) ||
							'		count(DISTINCT c.ID) NUM_CERTS' || chr(10) ||
							'	FROM certificate c';
			ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
				t_issuerCAID_table := 'c';
				t_query := 'SELECT c.ISSUER_CA_ID, ca.NAME,' || chr(10) ||
							'		encode(digest(x509_publickey(c.CERTIFICATE), ''sha1''), ''hex'') NAME_VALUE,' || chr(10) ||
							'		min(c.ID) MIN_CERT_ID,' || chr(10) ||
							'		count(DISTINCT c.ID) NUM_CERTS' || chr(10) ||
							'	FROM certificate c';
			ELSIF t_type = 'SHA-1(Subject)' THEN
				t_issuerCAID_table := 'c';
				t_query := 'SELECT c.ISSUER_CA_ID, ca.NAME,' || chr(10) ||
							'		encode(digest(x509_name(c.CERTIFICATE), ''sha1''), ''hex'') NAME_VALUE,' || chr(10) ||
							'		min(c.ID) MIN_CERT_ID,' || chr(10) ||
							'		count(DISTINCT c.ID) NUM_CERTS' || chr(10) ||
							'	FROM certificate c';
			ELSE
				t_issuerCAID_table := 'ci';
				t_query := 'SELECT ci.ISSUER_CA_ID, ca.NAME,' || chr(10) ||
							'		ci.NAME_VALUE,' || chr(10) ||
							'		min(ci.CERTIFICATE_ID) MIN_CERT_ID,' || chr(10) ||
							'		count(DISTINCT ci.CERTIFICATE_ID) NUM_CERTS' || chr(10) ||
							'	FROM certificate_identity ci';
			END IF;
			t_query := t_query || chr(10) ||
							'		LEFT OUTER JOIN ca ON (' || t_issuerCAID_table || '.ISSUER_CA_ID = ca.ID)';
			t_query := t_query || chr(10);

			IF t_type = 'CT Entry ID' THEN
				t_query := t_query ||
							'	WHERE ctle.ENTRY_ID = $1::integer' || chr(10) ||
							'		AND ctle.CT_LOG_ID = ctl.ID' || chr(10) ||
							'		AND ctle.CERTIFICATE_ID = c.ID' || chr(10);
			ELSIF t_type = 'Serial Number' THEN
				t_query := t_query ||
							'	WHERE x509_serialNumber(c.CERTIFICATE) = decode($1, ''hex'')' || chr(10);
			ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
				t_query := t_query ||
							'	WHERE digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')' || chr(10);
			ELSIF t_type = 'SHA-1(Subject)' THEN
				t_query := t_query ||
							'	WHERE digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')' || chr(10);
			ELSIF t_useReverseIndex THEN
				t_query := t_query ||
							'	WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))' || chr(10);
			ELSE
				t_query := t_query ||
							'	WHERE lower(ci.NAME_VALUE) LIKE lower($1)' || chr(10);
			END IF;
			IF t_type NOT IN ('CT Entry ID', 'Identity', 'Serial Number', 'SHA-1(SubjectPublicKeyInfo)', 'SHA-1(Subject)') THEN
				t_query := t_query ||
							'		AND ci.NAME_TYPE = ' || quote_literal(t_nameType) || chr(10);
			END IF;
			t_query := t_query ||
							'	GROUP BY ' || t_issuerCAID_table || '.ISSUER_CA_ID, ca.NAME, NAME_VALUE' || chr(10);

			t_query := t_query ||
							'	ORDER BY NUM_CERTS DESC, NAME_VALUE, NAME';

			t_showIdentity := (position('%' IN t_value) > 0) OR (t_type = 'CT Entry ID');

			t_text := '';
			FOR l_record IN EXECUTE t_query
							USING t_value LOOP
				t_text := t_text ||
'  <TR>
    <TD>';
				IF (l_record.NUM_CERTS = 1)
						AND (l_record.MIN_CERT_ID IS NOT NULL) THEN
					t_text := t_text || '<A href="?id=' || l_record.MIN_CERT_ID::text || '">'
								|| l_record.NUM_CERTS::text || '</A>';
				ELSIF (l_record.ISSUER_CA_ID IS NOT NULL)
						AND (l_record.MIN_CERT_ID IS NOT NULL) THEN
					t_text := t_text || '<A href="?' || t_paramName || '=' || urlEncode(l_record.NAME_VALUE);
					t_text := t_text || '&iCAID=' || l_record.ISSUER_CA_ID::text || '">'
								|| l_record.NUM_CERTS::text || '</A>';
				ELSE
					t_text := t_text || l_record.NUM_CERTS::text;
				END IF;
				t_text := t_text || '</TD>
    <TD>';
				IF t_showIdentity THEN
					t_text := t_text || html_escape(l_record.NAME_VALUE) || '</TD>
    <TD>';
				END IF;
				IF l_record.ISSUER_CA_ID IS NOT NULL THEN
					t_text := t_text || '<A href="?caid=' || l_record.ISSUER_CA_ID::text || '">'
								|| coalesce(html_escape(l_record.NAME), '&nbsp;')
								|| '</A>';
				ELSE
					t_text := t_text || coalesce(html_escape(l_record.NAME), '?');
				END IF;
				t_text := t_text ||
'    </TD>
  </TR>
';
			END LOOP;

			t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Certificates</TH>
    <TD class="outer">';
			IF t_text != '' THEN
				t_output := t_output || '
<TABLE>
  <TR>
    <TH>#</TH>
';
				IF t_showIdentity THEN
					IF t_type = 'CT Entry ID' THEN
						t_output := t_output ||
'    <TH>CT Log</TH>
';
					ELSE
						t_output := t_output ||
'    <TH>Identity</TH>
';
					END IF;
				END IF;
				t_output := t_output ||
'    <TH>Issuer Name</TH>
  </TR>
' || t_text ||
'</TABLE>
';
			ELSE
				t_output := t_output ||
'<I>None found</I>';
			END IF;

			t_output := t_output || '</TD>
  </TR>
</TABLE>
';
		END IF;

	ELSE
		t_output := t_output || ' <SPAN class="whiteongrey">Error</SPAN>
<BR><BR>''' || name || ''' is an unsupported action!
';

	END IF;

	t_output := t_output || '
  <BR><BR><BR>
';
	IF coalesce(get_parameter('showSQL', paramNames, paramValues), 'N') = 'Y' THEN
		IF t_query IS NOT NULL THEN
			t_output := t_output || '<BR><BR><TEXTAREA cols="80" rows="25">' || t_query || ';</TEXTAREA>';
		END IF;
	END IF;
	t_output := t_output || '
  <P class="copyright">&copy; COMODO CA Limited 2015-2016. All rights reserved.</P>
  <DIV>
    <A href="https://github.com/crtsh"><IMG src="/GitHub-Mark-32px.png"></A>
  </DIV>
</BODY>
</HTML>';

	RETURN t_output;

EXCEPTION
	WHEN no_data_found THEN
		RETURN coalesce(t_output, '') || '<BR><BR>' || SQLERRM ||
'</BODY>
</HTML>
';
	WHEN others THEN
		GET STACKED DIAGNOSTICS t_temp = PG_EXCEPTION_CONTEXT;
		RETURN coalesce(t_output, '') || '<BR><BR>' || SQLERRM || '<BR><BR>' || html_escape(t_temp) || '<BR><BR>' || html_escape(t_query);
END;
$$ LANGUAGE plpgsql;
