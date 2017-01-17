/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2017 COMODO CA Limited
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
		'ski', 'Subject Key Identifier', NULL,
		'spkisha1', 'SHA-1(SubjectPublicKeyInfo)', NULL,
		'spkisha256', 'SHA-256(SubjectPublicKeyInfo)', NULL,
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
		's', 'Simple', NULL,
		'cablint', 'CA/B Forum lint', NULL,
		'x509lint', 'X.509 lint', NULL,
		'lint', 'Lint', NULL
	];
	t_paramNo			integer;
	t_paramName			text;
	t_value				text;
	t_type				text			:= 'Simple';
	t_cmd				text;
	t_bytea				bytea;
	t_output			text;
	t_outputType		text;
	t_title				text;
	t_summary			text;
	t_b64Certificate	text;
	t_certificateID		certificate.ID%TYPE;
	t_certificateSHA1	bytea;
	t_certificateSHA256	bytea;
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_caID				ca.ID%TYPE;
	t_caName			ca.NAME%TYPE;
	t_serialNumber		bytea;
	t_spkiSHA256		bytea;
	t_nameType			name_type;
	t_text				text;
	t_offset			integer;
	t_pos1				integer;
	t_temp0				text;
	t_temp				text;
	t_temp2				text;
	t_temp3				text;
	t_select			text;
	t_from				text;
	t_where				text;
	t_nameValue			text;
	t_certID_field		text;
	t_query				text;
	t_sort				integer;
	t_groupBy			text			:= 'none';
	t_groupByParameter	text			:= 'none';
	t_direction			text;
	t_oppositeDirection	text;
	t_dirSymbol			text;
	t_issuerO			text;
	t_issuerOParameter	text;
	t_orderBy			text			:= 'ASC';
	t_matchType			text			:= '=';
	t_opt				text;
	t_maxAge			timestamp;
	t_cacheResponse		boolean			:= FALSE;
	t_useCachedResponse	boolean			:= FALSE;
	t_linter			linter_type;
	t_linters			text;
	t_showCABLint		boolean;
	t_showX509Lint		boolean;
	t_showMetadata		boolean;
	t_certType			integer;
	t_showMozillaDisclosure	boolean;
	t_ctp				ca_trust_purpose%ROWTYPE;
	t_useReverseIndex	boolean			:= FALSE;
	t_joinToCertificate_table	text;
	t_joinToCTLogEntry	text;
	t_showIdentity		boolean;
	t_minNotBefore		timestamp;
	t_minNotBeforeString	text;
	t_excludeExpired	text;
	t_excludeAffectedCerts	text;
	t_excludeCAs		integer[];
	t_excludeCAsString	text;
	t_searchProvider	text;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_issuerCAID_table	text;
	t_feedUpdated		timestamp;
	t_incompleteCount	integer			:= 0;
	t_undisclosedCount	integer			:= 0;
	t_trustRevokedCount	integer			:= 0;
	t_notTrustedCount	integer			:= 0;
	t_constrainedCount	integer			:= 0;
	t_expiredCount		integer			:= 0;
	t_revokedCount		integer			:= 0;
	t_revokedViaOneCRLCount	integer		:= 0;
	t_disclosedCount	integer			:= 0;
	t_discErrorCount	integer			:= 0;
	t_unknownCount		integer			:= 0;
	t_caPublicKey		ca.PUBLIC_KEY%TYPE;
	t_count				integer;
	t_pageNo			integer;
	t_resultsPerPage	integer			:= 100;
	l_record			RECORD;
	l_record2			RECORD;
	t_purposeOID		text;
	t_cacheControlMaxAge	integer		:= 300;
BEGIN
	FOR t_paramNo IN 1..array_length(c_params, 1) LOOP
		IF t_cmd IS NULL THEN
			t_cmd := c_params[t_paramNo];
		END IF;
		IF t_value IS NULL THEN
			t_paramName := c_params[t_paramNo];
			t_value := coalesce(
				btrim(get_parameter(t_paramName, paramNames, paramValues)), ''
			);
		ELSIF t_value = '' THEN
			IF c_params[t_paramNo] IS NULL THEN
				t_value := NULL;
				t_cmd := NULL;
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
				BEGIN
					EXIT WHEN t_value::integer IS NOT NULL;
				EXCEPTION
					WHEN OTHERS THEN
						NULL;
				END;
			ELSIF t_type IN (
						'Simple', 'Advanced', 'CA/B Forum lint', 'X.509 lint', 'Lint', 'CA Name',
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
			ELSIF t_type IN (
						'SHA-256(Certificate)', 'SHA-256(SubjectPublicKeyInfo)'
					) THEN
				EXIT WHEN length(t_bytea) = 32;
			ELSIF t_type IN ('Serial Number', 'Subject Key Identifier') THEN
				EXIT WHEN t_bytea IS NOT NULL;
			ELSE
				t_type := 'Invalid value';
				EXIT;
			END IF;
		END IF;
	END LOOP;

	t_outputType := coalesce(get_parameter('output', paramNames, paramValues), '');
	IF t_outputType = '' THEN
		t_outputType := 'html';
	END IF;
	IF lower(t_outputType) IN ('forum', 'gen-add-chain') THEN
		t_type := lower(t_outputType);
		t_title := t_type;
		t_outputType := 'html';
	ELSIF lower(t_outputType) IN ('mozilla-disclosures', 'redacted-precertificates') THEN
		t_type := lower(t_outputType);
		t_title := t_type;
		t_outputType := 'html';
		t_useCachedResponse := TRUE;
	ELSIF lower(t_outputType) IN ('advanced') THEN
		t_type := 'Advanced';
		t_outputType := 'html';
	END IF;
	IF t_outputType NOT IN ('html', 'json', 'atom') THEN
		RAISE no_data_found USING MESSAGE = 'Unsupported output type: ' || html_escape(t_outputType);
	END IF;

	IF coalesce(t_type, 'Simple') = 'Simple' THEN
		t_type := 'Simple';
		t_outputType := 'html';
	END IF;

	IF t_type IN ('Simple', 'Advanced') THEN
		t_title := 'Certificate Search';
	ELSIF t_type IN (
				'SHA-1(Certificate)',
				'SHA-256(Certificate)',
				'SHA-1(SubjectPublicKeyInfo)',
				'SHA-256(SubjectPublicKeyInfo)',
				'SHA-1(Subject)'
			) THEN
		t_value := encode(t_bytea, 'hex');
	ELSIF t_type = 'CT Entry ID' THEN
		t_title := 'CT:' || t_value;
	ELSIF t_type IN ('CA ID', 'CA Name') THEN
		t_title := 'CA:' || t_value;
	ELSIF t_type = 'Serial Number' THEN
		t_value := encode(t_bytea, 'hex');
		t_title := 'Serial#' || t_value;
	ELSIF t_type = 'Subject Key Identifier' THEN
		t_value := encode(t_bytea, 'hex');
		t_title := 'SKI#' || t_value;
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
	ELSIF lower(t_type) LIKE '%lint' THEN
		IF t_type = 'Lint' THEN
			t_linters := 'cablint,x509lint';
		ELSE
			t_linters := t_cmd;
			t_linter := t_linters::linter_type;
		END IF;
		BEGIN
			IF lower(t_value) = 'issues' THEN
				t_type := t_type || ': Issues';
			ELSE
				t_value := (t_value::integer)::text;
			END IF;
		EXCEPTION
			WHEN OTHERS THEN
				t_type := t_type || ': Summary';
		END;
	END IF;

	IF t_title IS NULL THEN
		t_title := coalesce(t_value, '');
	END IF;

	t_temp := get_parameter('minNotBefore', paramNames, paramValues);
	IF t_temp IS NULL THEN
		t_minNotBefore := date_trunc('day', statement_timestamp() - interval '1 week');
		t_minNotBeforeString := '';
	ELSE
		t_minNotBefore := t_temp::timestamp;
		t_minNotBeforeString := '&minNotBefore=' || t_temp;
	END IF;

	t_temp := get_parameter('exclude', paramNames, paramValues);
	IF lower(coalesce(',' || t_temp || ',', 'nothing')) LIKE ',expired,' THEN
		t_excludeExpired := '&exclude=expired';
	END IF;

	t_temp := get_parameter('search', paramNames, paramValues);
	IF lower(coalesce(t_temp, 'crt.sh')) = 'censys' THEN
		t_searchProvider := '&search=censys';
	END IF;

	t_opt := coalesce(get_parameter('opt', paramNames, paramValues), '');
	IF t_opt != '' THEN
		t_opt := t_opt || ',';
	END IF;

	IF t_outputType = 'html' THEN
		IF lower(t_type) LIKE '%lint%' THEN
			t_groupBy := coalesce(get_parameter('group', paramNames, paramValues), '');
			t_direction := coalesce(get_parameter('dir', paramNames, paramValues), 'v');
		ELSE
			t_groupBy := coalesce(get_parameter('group', paramNames, paramValues), 'none');
			t_direction := coalesce(get_parameter('dir', paramNames, paramValues), '^');
		END IF;

		t_groupByParameter := t_groupBy;
		IF t_groupByParameter != '' THEN
			t_groupByParameter := '&group=' || t_groupByParameter;
		END IF;

		IF t_direction NOT IN ('^', 'v') THEN
			t_direction := 'v';
		END IF;
		IF t_direction = 'v' THEN
			t_dirSymbol := '&#8681;';
			t_orderBy := 'ASC';
			t_oppositeDirection := '^';
		ELSE
			t_dirSymbol := '&#8679;';
			t_orderBy := 'DESC';
			t_oppositeDirection := 'v';
		END IF;
	END IF;

	t_temp := get_parameter('sort', paramNames, paramValues);
	IF coalesce(t_temp, '') = '' THEN
		t_sort := 1;
	ELSE
		t_sort := t_temp::integer;
	END IF;

	t_excludeCAs := string_to_array(coalesce(get_parameter('excludecas', paramNames, paramValues), ''), ',');
	IF array_length(t_excludeCAs, 1) > 0 THEN
		t_excludeCAsString := '&excludeCAs=' || array_to_string(t_excludeCAs, ',');
	END IF;

	IF t_useCachedResponse THEN
		t_count := coalesce(get_parameter('maxage', paramNames, paramValues), '1200')::integer;
		t_cacheResponse := (t_count = 0);
		t_maxAge := statement_timestamp() - (interval '1 second' * t_count);
		SELECT cr.RESPONSE_BODY
			INTO t_output
			FROM cached_response cr
			WHERE cr.PAGE_NAME = t_type
				AND cr.GENERATED_AT > t_maxAge;
		IF FOUND THEN
			RETURN t_output;
		END IF;
	END IF;

	-- Generate page header.
	t_output := '';
	IF t_outputType = 'html' THEN
		t_output :=
'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
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
      text-align: center
    }
    form {
      margin: 0px
    }
    span.heading {
      color: #888888;
      font: 12pt Arial, sans-serif
    }
    span.title {
      border: 1px solid;
      color: #BF2E1A;
      font: bold 18pt Arial, sans-serif;
      padding: 0px 5px
    }
    span.text {
      color: #888888;
      font: 10pt Arial, sans-serif
    }
    span.whiteongrey {
      background-color: #CCCCCC;
      border: 1px solid;
      color: #FFFFFF;
      font: bold 18pt Arial, sans-serif;
      padding: 0px 5px
    }
    table {
      border-collapse: collapse;
      color: #222222;
      font: 10pt Arial, sans-serif;
      margin-left: auto;
      margin-right: auto
    }
    table.options {
      border: none;
      margin-left: 10px
    }
    td, th {
      border: 1px solid #CCCCCC;
      padding: 0px 2px;
      text-align: left;
      vertical-align: top
    }
    td.outer, th.outer {
      border: 1px solid #CCCCCC;
      padding: 2px 20px;
      text-align: left
    }
    th.heading {
      color: #888888;
      font: bold italic 12pt Arial, sans-serif;
      padding: 20px 0px 0px;
      text-align: center
    }
    th.options, td.options {
      border: none;
      vertical-align: middle
    }
    td.text {
      font: 10pt Courier New, sans-serif;
      padding: 2px 20px
    }
    td.heading {
      border: none;
      color: #888888;
      font: 12pt Arial, sans-serif;
      padding-top: 20px;
      text-align: center
    }
    table.lint td, th {
      text-align: center
    }
    .button {
      background-color: #BF2E1A;
      color: #FFFFFF;
      font: 13pt Arial, sans-serif
    }
    .copyright {
      font: 8pt Arial, sans-serif;
      color: #DF4F3C
    }
    .input {
      border: 1px solid #888888;
      font-weight: bold;
      text-align: center
    }
    .small {
      font: 8pt Arial, sans-serif;
      color: #888888
    }
    .error {
      background-color: #FFDFDF;
      color: #CC0000;
      font-weight: bold
    }
    .fatal {
      background-color: #0000AA;
      color: #FFFFFF;
      font-weight: bold
    }
    .notice {
      background-color: #FFFFDF;
      color: #606000
    }
    .warning {
      background-color: #FFEFDF;
      color: #DF6000
    }
  </STYLE>
</HEAD>
<BODY>
  <A href="?"><SPAN class="title">crt.sh</SPAN></A>';
	END IF;

	IF t_type = 'Invalid value' THEN
		RAISE no_data_found USING MESSAGE = t_type || ': ''' || html_escape(t_value) || '''';

	ELSIF t_type = 'Simple' THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
  <BR><BR><BR><BR>
  Enter an <B>Identity</B> (Domain Name, Organization Name, etc),
  <BR>a <B>Certificate Fingerprint</B> (SHA-1 or SHA-256) or a <B>crt.sh ID</B>:
  <BR><SPAN class="small" style="color:#BBBBBB">(% = wildcard)</SPAN>
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
  <BR><BR><BR>
  <SCRIPT type="text/javascript">
    function doSearch(
      type,
      value
    )
    {
      if ((!type) || (!value))
        return;
      var t_url;
      if (document.search_form.searchCensys.checked && (type != "CAID")) {
        if ((type == "id") || (type == "ctid") || (type == "ski")
             || (type == "spkisha1") || (type == "spkisha256")
             || (type == "subjectsha1") || (type == "E")) {
          alert("Sorry, Censys doesn''t support this search type");
          return;
        }
        t_url = "//www.censys.io/certificates?q=";
        var t_field = "";
        if (value != "%") {
          if (type == "c")
            t_url += "parsed.fingerprint_sha1:" + encodeURIComponent("\"" + value.toLowerCase() + "\"")
                     + " OR parsed.fingerprint_sha256:" + encodeURIComponent("\"" + value.toLowerCase() + "\"");
          else if (type == "serial")
            t_field = "parsed.serial_number";
          else if (type == "sha1")
            t_url += "parsed.fingerprint_sha1:" + encodeURIComponent("\"" + value.toLowerCase() + "\"");
          else if (type == "sha256")
            t_url += "parsed.fingerprint_sha256:" + encodeURIComponent("\"" + value.toLowerCase() + "\"");
          else if ((type == "CA") || (type == "CAName"))
            t_field = "parsed.issuer_dn";
          else if (type == "Identity")
            t_url += "parsed.subject_dn:" + encodeURIComponent("\"" + value + "\"")
                     + " OR parsed.extensions.subject_alt_name.dns_names:" + encodeURIComponent("\"" + value + "\"")
                     + " OR parsed.extensions.subject_alt_name.email_addresses:" + encodeURIComponent("\"" + value + "\"")
                     + " OR parsed.extensions.subject_alt_name.ip_addresses:" + encodeURIComponent("\"" + value + "\"");
          else if (type == "CN")
            t_field = "parsed.subject.common_name";
          else if (type == "OU")
            t_field = "parsed.subject.organizational_unit";
          else if (type == "O")
            t_field = "parsed.subject.organization";
          else if (type == "dNSName")
            t_field = "parsed.extensions.subject_alt_name.dns_names";
          else if (type == "rfc822Name")
            t_field = "parsed.extensions.subject_alt_name.email_addresses";
          else if (type == "iPAddress")
            t_field = "parsed.extensions.subject_alt_name.ip_addresses";
        }
        if (t_field != "")
          t_url += t_field + ":" + encodeURIComponent("\"" + value + "\"");
      }
      else {
        t_url = "?" + encodeURIComponent(type) + "=" + encodeURIComponent(value).replace(/%20/g, "+");
        if (document.search_form.excludeExpired.checked)
          t_url += "&exclude=expired";
        if (document.search_form.searchCensys.checked)
          t_url += "&search=censys";
      }
      window.location = t_url;
    }
  </SCRIPT>
  <FORM name="search_form" method="GET" onsubmit="return false">
    Enter search term:
    <SPAN class="small" style="position:absolute;padding-top:3px;color:#BBBBBB">&nbsp;(% = wildcard)</SPAN>
    <BR><BR>
    <INPUT type="text" class="input" name="q" size="64" maxlength="255">
    <BR><BR><BR>
    <TABLE class="options" style="margin:auto">
      <TR>
        <TD style="border:none;text-align:center">
          <SPAN class="heading">Select search type:</SPAN>
          <BR><SELECT name="searchtype" size="19">
            <OPTION value="c">CERTIFICATE</OPTION>
            <OPTION value="id">&nbsp; crt.sh ID</OPTION>
            <OPTION value="ctid">&nbsp; CT Entry ID</OPTION>
            <OPTION value="serial">&nbsp; Serial Number</OPTION>
            <OPTION value="ski">&nbsp; Subject Key Identifier</OPTION>
            <OPTION value="spkisha1">&nbsp; SHA-1(SubjectPublicKeyInfo)</OPTION>
            <OPTION value="spkisha256">&nbsp; SHA-256(SubjectPublicKeyInfo)</OPTION>
            <OPTION value="subjectsha1">&nbsp; SHA-1(Subject)</OPTION>
            <OPTION value="sha1">&nbsp; SHA-1(Certificate)</OPTION>
            <OPTION value="sha256">&nbsp; SHA-256(Certificate)</OPTION>
            <OPTION value="ca">CA</OPTION>
            <OPTION value="CAID">&nbsp; ID</OPTION>
            <OPTION value="CAName">&nbsp; Name</OPTION>
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
        <TD style="border:none;width:40px">&nbsp;</TD>
        <TD style="border:none;text-align:center">
          <SPAN class="heading">Select search options:</SPAN>
          <BR><DIV style="border:1px solid #AAAAAA;margin-bottom:5px;padding:5px 0px;text-align:left">
            <INPUT type="checkbox" name="excludeExpired"';
		IF t_excludeExpired IS NOT NULL THEN
			t_output := t_output || ' checked';
		END IF;
		t_output := t_output || '> Exclude expired certificates?
            <BR><INPUT type="checkbox" name="searchCensys"';
		IF coalesce(t_searchProvider, '') = '&search=censys' THEN
			t_output := t_output || ' checked';
		END IF;
		t_output := t_output || '> Search on <SPAN style="vertical-align:-30%"><IMG src="/censys.png"></SPAN>?
          </DIV>
          <BR>
          <INPUT type="submit" class="button" value="Search"
                 onClick="doSearch(document.search_form.searchtype.value,document.search_form.q.value)">
          <SPAN style="position:absolute">
            &nbsp; &nbsp; &nbsp;
            <A style="font-size:8pt;vertical-align:sub" href="?">Simple...</A>
          </SPAN>
          <BR><BR><BR><BR><HR><BR>
          <SPAN class="heading">Select linting options:</SPAN>
          <BR><SELECT name="linter" size="3">
            <OPTION value="cablint" selected>cablint</OPTION>
            <OPTION value="x509lint">x509lint</OPTION>
            <OPTION value="lint">Both</OPTION>
          </SELECT>
          <SELECT name="linttype" size="3">
            <OPTION value="1 week" selected>1-week Summary</OPTION>
            <OPTION value="issues">Issues</OPTION>
          </SELECT>
          <BR><BR>
          <INPUT type="submit" class="button" value="Lint"
                 onClick="doSearch(document.search_form.linter.value,document.search_form.linttype.value)">
        </TD>
      </TR>
    </TABLE>
  </FORM>
  <SCRIPT type="text/javascript">
    document.search_form.q.focus();
  </SCRIPT>
  <BR>
  <TABLE>
    <TR><TD colspan="8" class="heading">CT Logs currently monitored:</TD></TR>
    <TR>
      <TH>Operator</TH>
      <TH>URL</TH>
      <TH>Latest Entry #</TH>
      <TH>Latest STH</TH>
      <TH>MMD</TH>
      <TH>Last Contacted</TH>
      <TH>In Chrome?</TH>
    </TR>';
		FOR l_record IN (
					SELECT ctl.OPERATOR, ctl.URL,
							ctl.LATEST_ENTRY_ID, ctl.LATEST_UPDATE,
							ctl.LATEST_STH_TIMESTAMP, ctl.MMD_IN_SECONDS,
							CASE WHEN ctl.LATEST_STH_TIMESTAMP + (ctl.MMD_IN_SECONDS || ' seconds')::interval < statement_timestamp()
								THEN ' style="color:#FF0000"'
								ELSE ''
							END FONT_STYLE,
							ctl.INCLUDED_IN_CHROME, ctl.CHROME_ISSUE_NUMBER, ctl.NON_INCLUSION_STATUS
						FROM ct_log ctl
						WHERE ctl.IS_ACTIVE = 't'
						ORDER BY ctl.LATEST_ENTRY_ID DESC
				) LOOP
			t_output := t_output || '
    <TR>
      <TD' || l_record.FONT_STYLE || '>' || l_record.OPERATOR || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.URL || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.LATEST_ENTRY_ID::text || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || to_char(l_record.LATEST_STH_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce((l_record.MMD_IN_SECONDS / 60 / 60)::text, '?') || 'hrs</TD>
      <TD>' || to_char(l_record.LATEST_UPDATE, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD>
';
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '<A href="https://code.google.com/p/chromium/issues/detail?id='
									|| l_record.CHROME_ISSUE_NUMBER::text || '" target="_blank">';
				IF l_record.INCLUDED_IN_CHROME IS NOT NULL THEN
					t_output := t_output || coalesce(l_record.NON_INCLUSION_STATUS, 'M' || l_record.INCLUDED_IN_CHROME::text);
				ELSE
					t_output := t_output || coalesce(l_record.NON_INCLUSION_STATUS, 'Pending');
				END IF;
				t_output := t_output || '</A>' || chr(10);
			ELSIF l_record.NON_INCLUSION_STATUS IS NOT NULL THEN
				t_output := t_output || l_record.NON_INCLUSION_STATUS;
			END IF;
			t_output := t_output ||
'    </TR>';
		END LOOP;
		t_output := t_output || '
    <TR><TD colspan="8" class="heading">CT Logs no longer monitored:</TD></TR>
    <TR>
      <TH>Operator</TH>
      <TH>URL</TH>
      <TH>Latest Entry #</TH>
      <TH>Latest STH</TH>
      <TH>MMD</TH>
      <TH>Last Contacted</TH>
      <TH>In Chrome?</TH>
    </TR>';
		FOR l_record IN (
					SELECT ctl.OPERATOR, ctl.URL,
							ctl.LATEST_ENTRY_ID, ctl.LATEST_UPDATE,
							ctl.LATEST_STH_TIMESTAMP, ctl.MMD_IN_SECONDS,
							CASE WHEN ctl.LATEST_STH_TIMESTAMP + (ctl.MMD_IN_SECONDS || ' seconds')::interval < statement_timestamp()
								THEN ' style="color:#FF0000"'
								ELSE ''
							END FONT_STYLE,
							ctl.INCLUDED_IN_CHROME, ctl.CHROME_ISSUE_NUMBER, ctl.NON_INCLUSION_STATUS
						FROM ct_log ctl
						WHERE ctl.IS_ACTIVE = 'f'
							AND ctl.LATEST_ENTRY_ID IS NOT NULL
						ORDER BY ctl.LATEST_ENTRY_ID DESC
				) LOOP
			t_output := t_output || '
    <TR>
      <TD' || l_record.FONT_STYLE || '>' || l_record.OPERATOR || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.URL || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.LATEST_ENTRY_ID::text || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || to_char(l_record.LATEST_STH_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce((l_record.MMD_IN_SECONDS / 60 / 60)::text, '?') || 'hrs</TD>
      <TD>' || to_char(l_record.LATEST_UPDATE, 'YYYY-MM-DD HH24:MI:SS') || '</TD>
      <TD>
';
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '<A href="https://code.google.com/p/chromium/issues/detail?id='
									|| l_record.CHROME_ISSUE_NUMBER::text || '" target="_blank">';
				IF l_record.INCLUDED_IN_CHROME IS NOT NULL THEN
					t_output := t_output || coalesce(l_record.NON_INCLUSION_STATUS, 'M' || l_record.INCLUDED_IN_CHROME::text);
				ELSE
					t_output := t_output || coalesce(l_record.NON_INCLUSION_STATUS, 'Pending');
				END IF;
				t_output := t_output || '</A>' || chr(10);
			ELSIF l_record.NON_INCLUSION_STATUS IS NOT NULL THEN
				t_output := t_output || l_record.NON_INCLUSION_STATUS;
			END IF;
			t_output := t_output ||
'    </TR>';
		END LOOP;
		t_output := t_output || '
</TABLE>';

	ELSIF t_type = 'forum' THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Forum</SPAN>
<BR><BR>
<IFRAME id="forum_embed"
  src="javascript:void(0)"
  scrolling="no"
  frameborder="0"
  width="900"
  height="600">
</IFRAME>
<SCRIPT type="text/javascript">
  document.getElementById(''forum_embed'').src =
     ''https://groups.google.com/forum/embed/?place=forum/crtsh''
     + ''&showsearch=true&showpopout=true&showtabs=false''
     + ''&parenturl='' + encodeURIComponent(window.location.href);
</SCRIPT>';

	ELSIF t_type = 'redacted-precertificates' THEN
		t_output := t_output ||
'  <SPAN class="whiteongrey">Redacted Precertificates</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
';

		t_temp := '';
		FOR l_record IN (
					SELECT pc.ID PRECERT_ID,
							array_agg(pci.NAME_VALUE) REDACTED_LABELS,
							c.ID CERT_ID,
							pci.ISSUER_CA_ID,
							ca.NAME  ISSUER_NAME
						FROM certificate_identity pci, ca,
							certificate pc
								LEFT OUTER JOIN certificate c ON (
									pc.ID != c.ID
									AND pc.ISSUER_CA_ID = c.ISSUER_CA_ID
									AND x509_serialNumber(pc.CERTIFICATE) = x509_serialNumber(c.CERTIFICATE)
									AND c.CERTIFICATE IS NOT NULL
								)
						WHERE lower(pci.NAME_VALUE) LIKE '?%'
							AND pci.NAME_TYPE IN ('dNSName', 'commonName')
							AND pci.ISSUER_CA_ID = ca.ID
							AND pci.CERTIFICATE_ID = pc.ID
						GROUP BY pc.ID, c.ID, pci.ISSUER_CA_ID, ca.NAME
						ORDER BY pc.ID DESC
				) LOOP
			t_temp := t_temp ||
'  <TR>
    <TD><A href="/?id=' || l_record.PRECERT_ID || '">' || l_record.PRECERT_ID || '</A></TD>
    <TD>' || array_to_string(l_record.REDACTED_LABELS, '<BR>') || '</TD>
';
			IF l_record.CERT_ID IS NULL THEN
				t_temp := t_temp ||
'    <TD>&nbsp;</TD>
    <TD>&nbsp;</TD>
    <TD>&nbsp;</TD>
';
			ELSE
				SELECT string_agg(ci.NAME_VALUE, '<BR>')
					INTO t_temp2
					FROM certificate_identity ci
					WHERE ci.CERTIFICATE_ID = l_record.CERT_ID
						AND ci.NAME_TYPE IN ('dNSName', 'commonName');
				t_temp := t_temp ||
'    <TD><A href="/?id=' || l_record.CERT_ID || '">' || l_record.CERT_ID || '</A></TD>
    <TD>' || t_temp2 || '</TD>
    <TD><A href="/?id=' || l_record.ISSUER_CA_ID || '">' || l_record.ISSUER_NAME || '</A></TD>
';
			END IF;
			t_temp := t_temp ||
'  </TR>
';
		END LOOP;
		t_output := t_output ||
'<TABLE>
  <TR>
    <TH>Precertificate</TH>
    <TH>Redacted Labels</TH>
    <TH>Certificate</TH>
    <TH>Unredacted Labels</TH>
    <TH>Issuer Name</TH>
  </TR>
'  || t_temp || '
</TABLE>';

	ELSIF t_type = 'gen-add-chain' THEN
		t_temp := get_parameter('b64cert', paramNames, paramValues);
		IF t_temp IS NULL THEN
			t_output := t_output ||
'<BR><BR>1. Enter a base64 encoded certificate.
<BR><BR>2. Press the button to generate JSON that you can then submit to a log''s /ct/v1/add-chain API.
<BR>(crt.sh will discover the trust chain for you).
<BR><BR><FORM>
  <TEXTAREA name="b64cert" rows=25 cols=64></TEXTAREA>
  <BR><BR><INPUT type="submit" class="button" value="Generate JSON">
</FORM>
<BR><BR><SPAN class="small">Please note: This tool currently finds chains that are trusted by the Mozilla and/or Microsoft and/or Apple root programs.
<BR>FIXME: Look at each log''s /ct/v1/get-roots instead</SPAN>';
		ELSE
			t_certificate := decode(
				replace(replace(t_temp, '-----BEGIN CERTIFICATE-----', ''), '-----END CERTIFICATE-----', ''),
				'base64'
			);

			RETURN
'[BEGIN_HEADERS]
Content-Disposition: attachment; filename="add-chain-' || encode(digest(t_certificate, 'sha256'), 'hex') || '.json"
Content-Type: application/json
[END_HEADERS]
' || generate_add_chain_body(t_certificate);
		END IF;

	ELSIF t_type = 'mozilla-disclosures' THEN
		t_output := t_output ||
'  <SPAN class="whiteongrey">Mozilla Disclosures</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
';

		t_temp := '';
		FOR l_record IN (
					SELECT md.CA_OWNER_OR_CERT_NAME, md.INCLUDED_CERTIFICATE_ID, md.INCLUDED_CERTIFICATE_OWNER,
							md.RECORD_TYPE,
							md.ISSUER_O, md.ISSUER_CN, md.SUBJECT_O, md.SUBJECT_CN, md.CERT_SHA256, md.SALESFORCE_ID,
							ic.CERTIFICATE_ID, ic.PROBLEMS
						FROM mozilla_disclosure md
								LEFT OUTER JOIN invalid_certificate ic
									ON (md.CERT_SHA256 = digest(ic.CERTIFICATE_AS_LOGGED, 'sha256'))
						WHERE md.CERTIFICATE_ID IS NULL
						ORDER BY (ic.PROBLEMS IS NOT NULL), md.INCLUDED_CERTIFICATE_OWNER,
								md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_unknownCount := t_unknownCount + 1;
			t_temp := t_temp ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp := t_temp || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp := t_temp || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp := t_temp || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp := t_temp || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp := t_temp || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp := t_temp || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp := t_temp || '</A>';
			END IF;
			t_temp := t_temp || '</TD>
    <TD style="font-family:monospace">' || upper(encode(l_record.CERT_SHA256, 'hex')) || '</TD>
    <TD>' || coalesce(html_escape(l_record.PROBLEMS), '&nbsp;');
			IF l_record.CERTIFICATE_ID IS NOT NULL THEN
				t_temp := t_temp || '.<BR><A href="/?id=' || l_record.CERTIFICATE_ID::text || '">View the correct encoding of this certificate</A>';
			END IF;
			t_temp := t_temp || '</TD>
  </TR>
';
		END LOOP;
		t_temp :=
'<BR><BR><SPAN class="title"><A name="unknown">Disclosed; Unknown to crt.sh or Incorrectly Encoded</A></SPAN>
<SPAN class="whiteongrey">' || t_unknownCount::text || ' CA certificates</SPAN>
<BR>
<TABLE>
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
    <TH>Encoding Problems?</TH>
  </TR>
' || t_temp;
		IF t_unknownCount = 0 THEN
			t_temp := t_temp ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp := t_temp ||
'</TABLE>
';

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'DisclosedWithErrors'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_discErrorCount := t_discErrorCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#F2A2E8"><A name="disclosedwitherrors">Disclosed, but with Errors: Parent Certificate Name is set incorrectly</A></SPAN>
<SPAN class="whiteongrey">' || t_discErrorCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#F2A2E8">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_discErrorCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'Disclosed'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_disclosedCount := t_disclosedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#F2A2E8"><A name="disclosed">Disclosed</A></SPAN>
<SPAN class="whiteongrey">' || t_disclosedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#F2A2E8">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_disclosedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'RevokedViaOneCRL'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_revokedViaOneCRLCount := t_revokedViaOneCRLCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#B2CEFE"><A name="revokedviaonecrl">Disclosed and Revoked via OneCRL</A></SPAN>
<SPAN class="whiteongrey">' || t_revokedViaOneCRLCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#B2CEFE">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_revokedViaOneCRLCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'Revoked'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_revokedCount := t_revokedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#B2CEFE"><A name="revoked">Disclosed as Revoked, but not currently in OneCRL</A></SPAN>
<SPAN class="whiteongrey">' || t_revokedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#B2CEFE">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_revokedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'Expired'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_expiredCount := t_expiredCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#BAED91"><A name="expired">Expired: Disclosure is not required</A></SPAN>
<SPAN class="whiteongrey">' || t_expiredCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#BAED91">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_expiredCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'TechnicallyConstrained'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_constrainedCount := t_constrainedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#BAED91"><A name="constrained">Technically Constrained: Disclosure is not required</A></SPAN>
<SPAN class="whiteongrey">' || t_constrainedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#BAED91">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_constrainedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'NoKnownServerAuthTrustPath'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_notTrustedCount := t_notTrustedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#FAF884"><A name="nottrusted">Unconstrained for id-kp-serverAuth, but no unexpired trust paths have been observed: Disclosure is not known to be required</A></SPAN>
<SPAN class="whiteongrey">' || t_notTrustedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#FAF884">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_notTrustedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'AllServerAuthPathsRevoked'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_trustRevokedCount := t_trustRevokedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#F8B88B"><A name="trustrevoked">Unconstrained id-kp-serverAuth Trust, although all unexpired paths contain at least one revoked intermediate: Disclosure is not known to be required</A></SPAN>
<SPAN class="whiteongrey">' || t_trustRevokedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#F8B88B">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_trustRevokedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT md.INCLUDED_CERTIFICATE_OWNER, count(*) NUM_CERTS
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'Undisclosed'
							AND md.CERTIFICATE_ID IS NOT NULL
						GROUP BY md.INCLUDED_CERTIFICATE_OWNER
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER
				) LOOP
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '<I>Unknown</I>') || '</TD>
    <TD>' || l_record.NUM_CERTS::text || '</TD>
  </TR>
';
		END LOOP;
		IF t_temp2 != '' THEN
			t_temp :=
'<A name="undisclosedsummary"><BR></A><TABLE style="background-color:#FE838A">
  <TR>
    <TH>Root Owner</TH>
    <TH># of Certificates Requiring Disclosure</TH>
  </TR>
' || t_temp2 || '
</TABLE>
' || t_temp;
		END IF;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'Undisclosed'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_undisclosedCount := t_undisclosedCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>' || t_undisclosedCount::text || '</TD>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#FEA3AA"><A name="undisclosed">Unconstrained id-kp-serverAuth Trust: Disclosure is required!</A></SPAN>
<SPAN class="whiteongrey">' || t_undisclosedCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#FEA3AA">
  <TR>
    <TH>#</TH>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Subject CN</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_undisclosedCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_temp2 := '';
		FOR l_record IN (
					SELECT md.INCLUDED_CERTIFICATE_OWNER, count(*) NUM_CERTS
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'DisclosureIncomplete'
							AND md.CERTIFICATE_ID IS NOT NULL
						GROUP BY md.INCLUDED_CERTIFICATE_OWNER
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER
				) LOOP
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '<I>Unknown</I>') || '</TD>
    <TD>' || l_record.NUM_CERTS::text || '</TD>
  </TR>
';
		END LOOP;
		IF t_temp2 != '' THEN
			t_temp :=
'<A name="disclosureincompletesummary"><BR></A><TABLE style="background-color:#FE838A">
  <TR>
    <TH>Root Owner</TH>
    <TH># of Certificates Requiring Further Disclosure</TH>
  </TR>
' || t_temp2 || '
</TABLE>
' || t_temp;
		END IF;

		t_temp2 := '';
		FOR l_record IN (
					SELECT *
						FROM mozilla_disclosure md
						WHERE md.DISCLOSURE_STATUS = 'DisclosureIncomplete'
							AND md.CERTIFICATE_ID IS NOT NULL
						ORDER BY md.INCLUDED_CERTIFICATE_OWNER, md.ISSUER_O, md.ISSUER_CN NULLS FIRST, md.RECORD_TYPE DESC,
								md.SUBJECT_O, md.SUBJECT_CN NULLS FIRST
				) LOOP
			t_incompleteCount := t_incompleteCount + 1;
			t_temp2 := t_temp2 ||
'  <TR>
    <TD>';
			IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
				t_temp2 := t_temp2 || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
			ELSE
				t_temp2 := t_temp2 || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_O), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.ISSUER_CN), '&nbsp;') || '</TD>
    <TD>' || coalesce(html_escape(l_record.SUBJECT_O), '&nbsp;') || '</TD>
    <TD>';
			IF l_record.RECORD_TYPE = 'Root' THEN
				t_temp2 := t_temp2 || '<B>[Root]</B> ';
			END IF;
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">';
			END IF;
			t_temp2 := t_temp2 || coalesce(html_escape(l_record.CA_OWNER_OR_CERT_NAME), '&nbsp;');
			IF l_record.SALESFORCE_ID IS NOT NULL THEN
				t_temp2 := t_temp2 || '</A>';
			END IF;
			t_temp2 := t_temp2 || '</TD>
    <TD style="font-family:monospace"><A href="/?sha256=' || encode(l_record.CERT_SHA256, 'hex') || '&opt=mozilladisclosure" target="blank">' || substr(upper(encode(l_record.CERT_SHA256, 'hex')), 1, 16) || '...</A></TD>
  </TR>
';
		END LOOP;
		t_temp2 :=
'<BR><BR><SPAN class="title" style="background-color:#FE838A"><A name="disclosureincomplete">Certificate disclosed, but CP/CPS or Audit details missing: Further Disclosure is required!</A></SPAN>
<SPAN class="whiteongrey">' || t_incompleteCount::text || ' CA certificates</SPAN>
<BR>
<TABLE style="background-color:#FE838A">
  <TR>
    <TH>Root Owner / Certificate</TH>
    <TH>Issuer O</TH>
    <TH>Issuer CN</TH>
    <TH>Subject O</TH>
    <TH>Certificate Name / CA Community page</TH>
    <TH>SHA-256(Certificate)</TH>
  </TR>
' || t_temp2;
		IF t_incompleteCount = 0 THEN
			t_temp2 := t_temp2 ||
'  <TR><TD colspan="6">None found</TD></TR>
';
		END IF;
		t_temp2 := t_temp2 ||
'</TABLE>
';

		t_temp := t_temp2 || t_temp;

		t_output := t_output ||
'<TABLE>
  <TR>
    <TH>Category</TH>
    <TH>Disclosure Required?</TH>
    <TH># of CA certs</TH>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Disclosure Incomplete</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosureincomplete">' || t_incompleteCount::text || '</A>
      &nbsp;<A href="#disclosureincompletesummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#FEA3AA">
    <TD>Unconstrained id-kp-serverAuth Trust</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#undisclosed">' || t_undisclosedCount::text || '</A>
      &nbsp;<A href="#undisclosedsummary" style="font-size:8pt">Summary</A>
  </TR>
  <TR style="background-color:#F8B88B">
    <TD>Unconstrained, but all unexpired observed paths Revoked</TD>
    <TD>Unknown</TD>
    <TD><A href="#trustrevoked">' || t_trustRevokedCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#FAF884">
    <TD>Unconstrained, but zero unexpired observed paths</TD>
    <TD>Unknown</TD>
    <TD><A href="#nottrusted">' || t_notTrustedCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#BAED91">
    <TD>Technically Constrained</TD>
    <TD>Never</TD>
    <TD><A href="#constrained">' || t_constrainedCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#BAED91">
    <TD>Expired</TD>
    <TD>Never</TD>
    <TD><A href="#expired">' || t_expiredCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked (but not in OneCRL)</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revoked">' || t_revokedCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed and Revoked via OneCRL</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revokedviaonecrl">' || t_revokedViaOneCRLCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosed">' || t_disclosedCount::text || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but with Errors</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedwitherrors">' || t_discErrorCount::text || '</A></TD>
  </TR>
  <TR>
    <TD>Unknown to crt.sh or Incorrectly Encoded</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#unknown">' || t_unknownCount::text || '</TD>
  </TR>
</TABLE>
' || t_temp;

	ELSIF t_type IN (
				'ID',
				'SHA-1(Certificate)',
				'SHA-256(Certificate)',
				'Certificate ASN.1'
			)
			OR (
				(lower(',' || t_opt) LIKE '%,firstresult,%')
				AND (t_type = 'Serial Number')
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
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
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
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
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
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac
									ON (c.ID = cac.CERTIFICATE_ID)
				WHERE digest(c.CERTIFICATE, 'sha256') = t_bytea;
		ELSIF t_type = 'Serial Number' THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac
									ON (c.ID = cac.CERTIFICATE_ID)
				WHERE x509_serialNumber(c.CERTIFICATE) = t_bytea
				LIMIT 1;
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
		t_temp := '';
		IF t_opt != '' THEN
			t_temp := '&opt=' || RTRIM(t_opt, ',');
		END IF;
		IF t_issuerCAID IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Issuer:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?caid='
						|| t_issuerCAID::text
						|| t_temp || '">Issuer:</A><BR>'
			);
		END IF;
		IF t_caID IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subject:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?caid='
						|| t_caID::text
						|| t_temp || '">Subject:</A><BR>'
			);
		END IF;
		IF t_spkiSHA256 IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subject&nbsp;Public&nbsp;Key&nbsp;Info:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?spkisha256='
						|| encode(t_spkiSHA256, 'hex')
						|| '">Subject&nbsp;Public&nbsp;Key&nbsp;Info:</A><BR>'
			);
		END IF;
		t_text := replace(
			t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;X509v3&nbsp;Subject&nbsp;Key&nbsp;Identifier:&nbsp;<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?ski='
						|| coalesce(encode(x509_subjectKeyIdentifier(t_certificate), 'hex'), '')
						|| '">X509v3&nbsp;Subject&nbsp;Key&nbsp;Identifier:</A><BR>'
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
    <TD class="outer">';
		IF t_certificateID IS NOT NULL THEN
			t_output := t_output || '<A href="?id=' || t_certificateID::text || '">' || t_certificateID::text || '</A>';
		ELSE
			t_output := t_output || '<I>Not found</I>';
		END IF;
		t_output := t_output || '</TD>
  </TR>
';

		t_showMetadata := lower(',' || t_opt) NOT LIKE '%,nometadata,%';
		IF t_showMetadata THEN
			t_output := t_output ||
'  <TR>
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
						|| '&nbsp; <FONT class="small">'
						|| to_char(l_record.ENTRY_TIMESTAMP, 'HH24:MI:SS GMT')
						|| '</FONT></TD>
    <TD>' || l_record.ENTRY_ID::text || '</TD>
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
    <TH>Log Operator</TH>
    <TH>Log URL</TH>
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
';

			IF t_caID IS NOT NULL THEN
				t_output := t_output ||
'  <TR>
    <TH class="outer">Audit details<BR>
      <DIV class="small" style="padding-top:3px">Disclosed via
        <A href="//mozillacaprogram.secure.force.com/CA/PublicAllIntermediateCerts" target="_blank">Mozilla</A></DIV>
    </TH>
    <TD class="outer">
';
				t_temp := NULL;
				FOR l_record IN (
							SELECT *
								FROM mozilla_disclosure md
								WHERE md.DISCLOSURE_STATUS IN ('Disclosed', 'DisclosedWithErrors')
									AND md.CERTIFICATE_ID = t_certificateID
						) LOOP
					t_temp := '';
					t_output := t_output ||
'<TABLE class="options" style="margin-left:0px">
  <TR>
    <TH>Auditor</TH>
    <TH>Standard Audit</TH>
    <TH>BR Audit</TH>
    <TH>Documents</TH>
    <TH>CA Community</TH>
    <TH>Root Owner / Certificate</TH>
  </TR>
  <TR>
    <TD>' || coalesce(l_record.AUDITOR, '') || '</TD>
    <TD>';
					IF coalesce(l_record.STANDARD_AUDIT_URL, '') NOT LIKE '%://%' THEN
						t_output := t_output || coalesce(l_record.STANDARD_AUDIT_URL, 'Not disclosed');
					ELSE
						t_output := t_output || '
      <A href="' || l_record.STANDARD_AUDIT_URL || '" target="_blank">' || l_record.STANDARD_AUDIT_DATE::text || '</A>
    ';
					END IF;
					t_output := t_output || '</TD>
    <TD>';
					IF coalesce(l_record.BR_AUDIT_URL, '') NOT LIKE '%://%' THEN
						t_output := t_output || coalesce(l_record.BR_AUDIT_URL, 'No');
					ELSE
						t_output := t_output || '
      <A href="' || l_record.BR_AUDIT_URL || '" target="_blank">Yes</A>
    ';
					END IF;
					t_output := t_output || '</TD>
    <TD>
';
					IF coalesce(l_record.CP_URL, '') != '' THEN
						t_output := t_output ||
'      <A href="' || l_record.CP_URL || '" target="blank">CP</A>
';
					END IF;
					IF coalesce(l_record.CPS_URL, '') != '' THEN
						t_output := t_output ||
'      <A href="' || l_record.CPS_URL || '" target="blank">CPS</A>
';
					END IF;
					t_output := t_output ||
'    </TD>
    <TD>';
					IF l_record.SALESFORCE_ID IS NOT NULL THEN
						t_output := t_output || '<A href="//mozillacacommunity.force.com/' || l_record.SALESFORCE_ID || '" target="_blank">' || l_record.SALESFORCE_ID || '</A>';
					ELSE
						t_output := t_output || '&nbsp;';
					END IF;
					t_output := t_output || '</TD>
    <TD>';
					IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
						t_output := t_output || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
					ELSE
						t_output := t_output || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '</A>';
					END IF;
					t_output := t_output || '</TD>
  </TR>
</TABLE>';
					EXIT;
				END LOOP;
				IF t_temp IS NULL THEN
					SELECT CASE WHEN md.DISCLOSURE_STATUS IN ('Revoked', 'RevokedViaOneCRL') THEN 'Disclosed as Revoked'
								WHEN md.DISCLOSURE_STATUS = 'DisclosureIncomplete' THEN 'Disclosure Incomplete'
							END
						INTO t_temp
						FROM mozilla_disclosure md
						WHERE md.CERTIFICATE_ID = t_certificateID;
					t_temp := coalesce(t_temp, 'Not Disclosed');
				END IF;
				t_output := t_output || t_temp || '
    </TD>
  </TR>
';
			END IF;

			SELECT '<SPAN style="color:#CC0000">Revoked'
					|| CASE coalesce(cr.REASON_CODE, 0)
							WHEN 1 THEN ' (keyCompromise)'
							WHEN 2 THEN ' (cACompromise)'
							WHEN 3 THEN ' (affiliationChanged)'
							WHEN 4 THEN ' (superseded)'
							WHEN 5 THEN ' (cessationOfOperation)'
							WHEN 6 THEN ' (certificateHold)'
							WHEN 7 THEN ' (privilegeWithdrawn)'
							WHEN 8 THEN ' (aACompromise)'
							ELSE ''
						END
					|| '</SPAN></TD><TD>Serial Number'
				INTO t_temp0
				FROM crl_revoked cr
				WHERE cr.CA_ID = t_issuerCAID
					AND cr.SERIAL_NUMBER = t_serialNumber;
			IF NOT FOUND THEN
				SELECT count(*)
					INTO t_count
					FROM crl
					WHERE crl.CA_ID = t_issuerCAID
						AND crl.ERROR_MESSAGE IS NULL
						AND crl.NEXT_UPDATE > statement_timestamp();
				IF t_count > 0 THEN
					t_temp0 := 'Not Revoked</TD><TD><SPAN style="color:#888888">n/a</SPAN>';
				ELSE
					SELECT min(ERROR_MESSAGE)
						INTO t_temp0
						FROM crl
						WHERE crl.CA_ID = t_issuerCAID
							AND crl.ERROR_MESSAGE IS NOT NULL;
					IF t_temp0 IS NOT NULL THEN
						t_temp0 := '&nbsp;<SPAN style="color:#888888;vertical-align:middle;font-size:70%">(' || html_escape(t_temp0) || ')</SPAN>&nbsp;';
					ELSE
						t_temp0 := 'n/a';
					END IF;
					t_temp0 := '<SPAN style="color:#FF9400">Unknown</SPAN></TD><TD><SPAN style="color:#888888">' || t_temp0 || '<SPAN>';
				END IF;
			END IF;

			SELECT '<SPAN style="color:#CC0000">Revoked</SPAN></TD><TD>' || gr.ENTRY_TYPE
				INTO t_temp
				FROM google_revoked gr
				WHERE gr.CERTIFICATE_ID = t_certificateID;
			t_temp := coalesce(t_temp, 'Not Revoked</TD><TD><SPAN style="color:#888888">n/a</SPAN>');

			SELECT '<SPAN style="color:#CC0000">Revoked</SPAN></TD><TD>MD5(PublicKey)'
				INTO t_temp2
				FROM microsoft_disallowedcert mdc
				WHERE mdc.CERTIFICATE_ID = t_certificateID;
			t_temp2 := coalesce(t_temp2, 'Not Revoked</TD><TD><SPAN style="color:#888888">n/a</SPAN>');

			SELECT '<SPAN style="color:#CC0000">Revoked</SPAN></TD><TD>Issuer Name, Serial Number'
				INTO t_temp3
				FROM mozilla_onecrl mo
				WHERE mo.CERTIFICATE_ID = t_certificateID;
			t_temp3 := coalesce(t_temp3, 'Not Revoked</TD><TD><SPAN style="color:#888888">n/a</SPAN>');

			t_output := t_output ||
'  <TR>
    <TH class="outer">Revocation</TH>
    <TD class="outer">
      <TABLE class="options" style="margin-left:0px">
        <TR>
          <TH>Mechanism</TH>
          <TH>Provider</TH>
          <TH>Status</TH>
          <TH>Revoked by <SPAN style="color:#888888;vertical-align:middle;font-size:70%">(Error)</SPAN></TH>
        </TR>
        <TR>
          <TD>CRL</TD>
          <TD>The CA</TD>
          <TD>' || t_temp0 || '</TD>
        </TR>
        <TR>
          <TD>CRLSet / Blacklist</TD>
          <TD>Google</TD>
          <TD>' || t_temp || '</TD>
        </TR>
        <TR>
          <TD>disallowedcert.stl</TD>
          <TD>Microsoft</TD>
          <TD>' || t_temp2 || '</TD>
        </TR>
        <TR>
          <TD>OneCRL</TD>
          <TD>Mozilla</TD>
          <TD>' || t_temp3 || '</TD>
        </TR>
      </TABLE>
    </TD>
  </TR>
  <TR>
    <TH class="outer">SHA-256(Certificate)</TH>
    <TD class="outer"><A href="//censys.io/certificates/' || coalesce(lower(encode(t_certificateSHA256, 'hex')), '') || '">'
						|| coalesce(upper(encode(t_certificateSHA256, 'hex')), '<I>Not found</I>') || '</A></TD>
  </TR>
  <TR>
    <TH class="outer">SHA-1(Certificate)</TH>
    <TD class="outer">' || coalesce(upper(encode(t_certificateSHA1, 'hex')), '<I>Not found</I>') || '</TD>
  </TR>
';
		END IF;

		t_showCABLint := (',' || t_opt) LIKE '%,cablint,%';
		IF t_showCABLint THEN
			t_output := t_output ||
'  <TR>
    <TH class="outer">CA/B Forum lint<BR>
      <DIV class="small" style="padding-top:3px">Powered by <A href="//github.com/awslabs/certlint" target="_blank">certlint</A></DIV>
    </TH>
    <TD class="text">
';
			FOR l_record IN (
						SELECT substr(CABLINT, 4) ISSUE_TEXT,
								CASE substr(CABLINT, 1, 2)
									WHEN 'B:' THEN 1
									WHEN 'I:' THEN 2
									WHEN 'N:' THEN 3
									WHEN 'F:' THEN 4
									WHEN 'E:' THEN 5
									WHEN 'W:' THEN 6
									ELSE 5
								END ISSUE_TYPE,
								CASE substr(CABLINT, 1, 2)
									WHEN 'B:' THEN '<SPAN>&nbsp; &nbsp; &nbsp;BUG:'
									WHEN 'I:' THEN '<SPAN>&nbsp; &nbsp; INFO:'
									WHEN 'N:' THEN '<SPAN class="notice">&nbsp; NOTICE:'
									WHEN 'F:' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
									WHEN 'E:' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
									WHEN 'W:' THEN '<SPAN class="warning">&nbsp;WARNING:'
									ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || substr(CABLINT, 1, 2)
								END ISSUE_HEADING
							FROM cablint_embedded(t_certificate) CABLINT
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

		t_showX509Lint := (',' || t_opt) LIKE '%,x509lint,%';
		IF t_showX509Lint THEN
			IF NOT x509_canIssueCerts(t_certificate) THEN
				t_certType := 0;
			ELSIF t_caID != t_issuerCAID THEN
				t_certType := 1;
			ELSE
				t_certType := 2;
			END IF;

			t_output := t_output ||
'  <TR>
    <TH class="outer">X.509 lint<BR>
      <DIV class="small" style="padding-top:3px">Powered by <A href="//github.com/kroeckx/x509lint" target="_blank">x509lint</A></DIV>
    </TH>
    <TD class="text">
';
			FOR l_record IN (
						SELECT substr(X509LINT, 4) ISSUE_TEXT,
								CASE substr(X509LINT, 1, 2)
									WHEN 'B:' THEN 1
									WHEN 'I:' THEN 2
									WHEN 'N:' THEN 3
									WHEN 'F:' THEN 4
									WHEN 'E:' THEN 5
									WHEN 'W:' THEN 6
									ELSE 5
								END ISSUE_TYPE,
								CASE substr(X509LINT, 1, 2)
									WHEN 'B:' THEN '<SPAN>&nbsp; &nbsp; &nbsp;BUG:'
									WHEN 'I:' THEN '<SPAN>&nbsp; &nbsp; INFO:'
									WHEN 'N:' THEN '<SPAN class="notice">&nbsp; NOTICE:'
									WHEN 'F:' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
									WHEN 'E:' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
									WHEN 'W:' THEN '<SPAN class="warning">&nbsp;WARNING:'
									ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || substr(X509LINT, 1, 2)
								END ISSUE_HEADING
							FROM x509lint_embedded(t_certificate, t_certType) X509LINT
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
			IF t_showMetadata THEN
				t_output := t_output ||
'      <BR><BR><A href="?asn1=' || t_certificateID::text || '&opt=' || t_opt || 'nometadata">Hide metadata</A>
';
			ELSE
				IF t_opt = 'nometadata,' THEN
					t_temp := '';
				ELSE
					t_temp := '&opt=' || rtrim(replace(t_opt, 'nometadata,', ''), ',');
				END IF;
				t_output := t_output ||
'      <BR><BR><A href="?asn1=' || t_certificateID::text || t_temp || '">Show metadata</A>
';
			END IF;
			IF NOT t_showCABLint THEN
				t_output := t_output ||
'      <BR><BR><A href="?asn1=' || t_certificateID::text || '&opt=' || t_opt || 'cablint">Run cablint</A>
';
			END IF;
			IF NOT t_showX509Lint THEN
				t_output := t_output ||
'      <BR><BR><A href="?asn1=' || t_certificateID::text || '&opt=' || t_opt || 'x509lint">Run x509lint</A>
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
      <SPAN class="small">
';
			IF t_showMetadata THEN
				t_output := t_output ||
'      <BR><BR><A href="?id=' || t_certificateID::text || '&opt=' || t_opt || 'nometadata">Hide metadata</A>
';
			ELSE
				IF t_opt = 'nometadata,' THEN
					t_temp := '';
				ELSE
					t_temp := '&opt=' || rtrim(replace(t_opt, 'nometadata,', ''), ',');
				END IF;
				t_output := t_output ||
'      <BR><BR><A href="?id=' || t_certificateID::text || t_temp || '">Show metadata</A>
';
			END IF;
			IF NOT t_showCABLint THEN
				t_output := t_output ||
'      <BR><BR><A href="?id=' || t_certificateID::text || '&opt=' || t_opt || 'cablint">Run cablint</A>
';
			END IF;
			IF NOT t_showX509Lint THEN
				t_output := t_output ||
'      <BR><BR><A href="?id=' || t_certificateID::text || '&opt=' || t_opt || 'x509lint">Run x509lint</A>
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
			SELECT ca.ID, ca.NAME, ca.PUBLIC_KEY
				INTO t_caID, t_caName, t_caPublicKey
				FROM ca
				WHERE ca.ID = t_value::integer;
			
			IF t_caName IS NULL THEN
				RAISE no_data_found USING MESSAGE = 'CA not found';
			ELSE
				t_text := html_escape(t_caName);
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

			t_showMozillaDisclosure := (',' || t_opt || ',') LIKE '%,mozilladisclosure,%';
			t_temp := '';
			IF t_opt != '' THEN
				t_temp := '&opt=' || RTRIM(t_opt, ',');
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
';
			IF t_showMozillaDisclosure THEN
				t_output := t_output ||
'    <TH style="white-space:nowrap">Mozilla Disclosure<BR><SPAN class="small">(id-kp-serverAuth)</SPAN></TH>
';
			END IF;
			t_output := t_output ||
'    <TH style="white-space:nowrap">crt.sh ID</TH>
    <TH style="white-space:nowrap">Not Before</TH>
    <TH style="white-space:nowrap">Not After</TH>
    <TH>Issuer Name</TH>
  </TR>
';
			FOR l_record IN (
						SELECT x509_issuerName(c.CERTIFICATE)	ISSUER_NAME,
								c.ID,
								c.ISSUER_CA_ID,
								c.CERTIFICATE,
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
';
				IF t_showMozillaDisclosure THEN
					t_temp3 := '<FONT color=#';
					SELECT ctp.*
						INTO t_ctp
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = l_record.ISSUER_CA_ID
							AND ctp.TRUST_CONTEXT_ID = 5
							AND ctp.TRUST_PURPOSE_ID = 1;
					IF NOT FOUND THEN
						t_temp3 := t_temp3 || '888888>Not Trusted';
						t_ctp.SHORTEST_CHAIN := NULL;
					ELSIF NOT t_ctp.IS_TIME_VALID THEN
						t_temp3 := t_temp3 || '888888>Expired';
					ELSE
						SELECT md.DISCLOSURE_STATUS
							INTO t_temp2
							FROM mozilla_disclosure md
							WHERE md.CERTIFICATE_ID = l_record.ID;
						IF FOUND AND (t_temp2 LIKE 'Revoked%') THEN
							t_temp3 := t_temp3 || 'CC0000>Revoked';
						ELSIF is_technically_constrained(l_record.CERTIFICATE) THEN
							t_temp3 := t_temp3 || '00CC00>Constrained';
						ELSIF t_ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE OR t_ctp.ALL_CHAINS_REVOKED_VIA_ONECRL THEN
							t_temp3 := t_temp3 || 'CC0000>All Paths Revoked';
						ELSIF t_ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED THEN
							t_temp3 := t_temp3 || '00CC00>All Paths Constrained';
						ELSE
							t_temp3 := t_temp3 || '00CC00>Valid';
						END IF;
					END IF;
					IF t_ctp.SHORTEST_CHAIN IS NOT NULL THEN
						t_temp3 := t_temp3 || ' <SPAN style="vertical-align:super;font-size:70%;color:#33A8FF">' || (t_ctp.SHORTEST_CHAIN + 1)::text || '</SPAN>';
					END IF;
					t_output := t_output ||
'    <TD style="white-space:nowrap">' || t_temp3 || '</FONT></TD>
';
				END IF;
				t_output := t_output ||
'    <TD><A href="?id=' || l_record.ID::text || t_temp || '">' || l_record.ID::text || '</A></TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || '</TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_AFTER, 'YYYY-MM-DD') || '</TD>
    <TD><A href="?caid=' || l_record.ISSUER_CA_ID::text || t_temp || '">' || html_escape(l_record.ISSUER_NAME) || '</A></TD>
  </TR>
';
			END LOOP;

			t_output := t_output ||
'</TABLE>
    </TD>
  </TR>
  <TR><TD colspan=2>&nbsp;</TD></TR>
';

			t_showCABLint := (',' || coalesce(get_parameter('opt', paramNames, paramValues), '') || ',') LIKE '%,cablint,%';
			IF t_showCABLint THEN
				t_output := t_output ||
'  <TR>
    <TH class="outer">CA/B Forum lint</TH>
    <TD class="outer">
      <TABLE class="options">
        <TR><TH colspan=3>For Issued Certificates with notBefore >= ' || to_char(t_minNotBefore, 'YYYY-MM-DD') || ':</TH><TR>
        <TR>
          <TH>Issue</TH>
          <TH># Affected Certs</TH>
        </TR>
';
				FOR l_record IN (
							SELECT count(DISTINCT lci.CERTIFICATE_ID) NUM_CERTS, li.ID, li.SEVERITY, li.ISSUE_TEXT,
									CASE li.SEVERITY
										WHEN 'F' THEN 1
										WHEN 'E' THEN 2
										WHEN 'W' THEN 3
										WHEN 'N' THEN 4
										WHEN 'I' THEN 5
										WHEN 'B' THEN 6
										ELSE 7
									END ISSUE_TYPE,
									CASE li.SEVERITY
										WHEN 'F' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
										WHEN 'E' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
										WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
										WHEN 'N' THEN '<SPAN class="notice">&nbsp; NOTICE:'
										WHEN 'I' THEN '<SPAN>&nbsp; &nbsp; INFO:'
										WHEN 'B' THEN '<SPAN>&nbsp; &nbsp; &nbsp;BUG:'
										ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || li.SEVERITY || ':'
									END ISSUE_HEADING
								FROM lint_cert_issue lci, lint_issue li
								WHERE lci.NOT_BEFORE >= t_minNotBefore
									AND lci.ISSUER_CA_ID = t_value::integer
									AND lci.LINT_ISSUE_ID = li.ID
									AND li.LINTER = 'cablint'
								GROUP BY li.ID, li.SEVERITY, li.ISSUE_TEXT
								ORDER BY ISSUE_TYPE, NUM_CERTS DESC
						) LOOP
					t_output := t_output ||
'        <TR>
          <TD class="text">' || l_record.ISSUE_HEADING || ' ' || l_record.ISSUE_TEXT || '&nbsp;</SPAN></TD>
          <TD><A href="?cablint=' || l_record.ID::text || '&iCAID=' || t_caID::text || t_minNotBeforeString || '">' || l_record.NUM_CERTS::text || '</A></TD>
        </TR>
';
				END LOOP;
				t_output := t_output ||
'      </TABLE>
    </TD>
  </TR>
';
			END IF;

			t_showX509Lint := (',' || coalesce(get_parameter('opt', paramNames, paramValues), '') || ',') LIKE '%,x509lint,%';
			IF t_showX509Lint THEN
				t_output := t_output ||
'  <TR>
    <TH class="outer">X.509 lint</TH>
    <TD class="outer">
      <TABLE class="options">
        <TR><TH colspan=3>For Issued Certificates with notBefore >= ' || to_char(t_minNotBefore, 'YYYY-MM-DD') || ':</TH><TR>
        <TR>
          <TH>Issue</TH>
          <TH># Affected Certs</TH>
        </TR>
';
				FOR l_record IN (
							SELECT count(DISTINCT lci.CERTIFICATE_ID) NUM_CERTS, li.ID, li.SEVERITY, li.ISSUE_TEXT,
									CASE li.SEVERITY
										WHEN 'F' THEN 1
										WHEN 'E' THEN 2
										WHEN 'W' THEN 3
										WHEN 'N' THEN 4
										WHEN 'I' THEN 5
										WHEN 'B' THEN 6
										ELSE 7
									END ISSUE_TYPE,
									CASE li.SEVERITY
										WHEN 'F' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
										WHEN 'E' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
										WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
										WHEN 'N' THEN '<SPAN class="notice">&nbsp; NOTICE:'
										WHEN 'I' THEN '<SPAN>&nbsp; &nbsp; INFO:'
										WHEN 'B' THEN '<SPAN>&nbsp; &nbsp; &nbsp;BUG:'
										ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || li.SEVERITY || ':'
									END ISSUE_HEADING
								FROM lint_cert_issue lci, lint_issue li
								WHERE lci.NOT_BEFORE >= t_minNotBefore
									AND lci.ISSUER_CA_ID = t_value::integer
									AND lci.LINT_ISSUE_ID = li.ID
									AND li.LINTER = 'x509lint'
								GROUP BY li.ID, li.SEVERITY, li.ISSUE_TEXT
								ORDER BY ISSUE_TYPE, NUM_CERTS DESC
						) LOOP
					t_output := t_output ||
'        <TR>
          <TD class="text">' || l_record.ISSUE_HEADING || ' ' || l_record.ISSUE_TEXT || '&nbsp;</SPAN></TD>
          <TD><A href="?x509lint=' || l_record.ID::text || '&iCAID=' || t_caID::text || t_minNotBeforeString || '">' || l_record.NUM_CERTS::text || '</A></TD>
        </TR>
';
				END LOOP;
				t_output := t_output ||
'      </TABLE>
    </TD>
  </TR>
';
			END IF;

			t_output := t_output ||
'  <TR>
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
          var t_url;
          if (document.search_form.searchCensys.checked) {
            t_url = "//www.censys.io/certificates?q="
                   + encodeURIComponent("parsed.issuer_dn=\"' || replace(t_caName, '"', '') || '\"");
            var t_field = "";
            if (value != "%") {
              if (type == "Identity") {
                t_url += " AND (parsed.subject_dn:" + encodeURIComponent("\"" + value + "\"")
                         + " OR parsed.extensions.subject_alt_name.dns_names:" + encodeURIComponent("\"" + value + "\"")
                         + " OR parsed.extensions.subject_alt_name.email_addresses:" + encodeURIComponent("\"" + value + "\"")
                         + " OR parsed.extensions.subject_alt_name.ip_addresses:" + encodeURIComponent("\"" + value + "\"")
                         + ")";
              }
              else if (type == "CN")
                t_field = "parsed.subject.common_name";
              else if (type == "E") {
                alert("Sorry, Censys doesn''t support ''emailAddress (Subject)'' searches");
                return false;
              }
              else if (type == "OU")
                t_field = "parsed.subject.organizational_unit";
              else if (type == "O")
                t_field = "parsed.subject.organization";
              else if (type == "dNSName")
                t_field = "parsed.extensions.subject_alt_name.dns_names";
              else if (type == "rfc822Name")
                t_field = "parsed.extensions.subject_alt_name.email_addresses";
              else if (type == "iPAddress")
                t_field = "parsed.extensions.subject_alt_name.ip_addresses";
            }
            if (t_field != "")
              t_url += " AND " + t_field + ":" + encodeURIComponent("\"" + value + "\"");
          }
          else {
            t_url = "?" + encodeURIComponent(type) + "=" + encodeURIComponent(value);
            if (document.search_form.caID.value != "")
              t_url += "&iCAID=" + document.search_form.caID.value;
            if (document.search_form.excludeExpired.checked)
              t_url += "&exclude=expired";
          }
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
            <TD class="options" style="padding-left:20px;vertical-align:top">
              <SPAN class="text">Search options:</SPAN>
              <BR><BR><DIV style="border:1px solid #AAAAAA;margin-bottom:8px;padding:5px 0px;text-align:left">
                <INPUT type="checkbox" name="excludeExpired"';
			IF t_excludeExpired IS NOT NULL THEN
				t_output := t_output || ' checked';
			END IF;
			t_output := t_output || '> Exclude expired certificates?
                <BR><INPUT type="checkbox" name="searchCensys"';
			IF coalesce(t_searchProvider, '') = '&search=censys' THEN
				t_output := t_output || ' checked';
			END IF;
			t_output := t_output || '> Search on <SPAN style="vertical-align:-30%"><IMG src="/censys.png"></SPAN>?
              </DIV>
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
    <TH class="outer">Trust</TH>
    <TD class="outer">
      <TABLE class="options" style="margin-left:0px">
        <TR>
          <TH rowspan="2" style="vertical-align:middle">Purpose</TH>
';

			t_text := '';
			t_count := 0;
			FOR l_record IN (
						SELECT *
							FROM trust_context tc
							ORDER BY tc.DISPLAY_ORDER
					) LOOP
				t_text := t_text ||
'          <TH><A href="' || l_record.URL || '" target="_blank">' || l_record.CTX || '</A>';
				IF l_record.VERSION IS NOT NULL THEN
					t_text := t_text || '<BR>';
					IF l_record.VERSION_URL IS NOT NULL THEN
						t_text := t_text || '<A href="' || l_record.VERSION_URL || '" target="_blank">';
					END IF;
					t_text := t_text || '<SPAN class="small">(' || l_record.VERSION || ')</SPAN>';
					IF l_record.VERSION_URL IS NOT NULL THEN
						t_text := t_text || '</A>';
					END IF;
				END IF;
				t_text := t_text || '</TH>
';
				t_count := t_count + 1;
			END LOOP;

			t_output := t_output ||
'          <TH colspan="' || t_count::text || '">Context <SPAN class="small">(Version)</SPAN> <SPAN style="vertical-align:super;font-size:70%;color:#33A8FF">Shortest Path</SPAN></TH>
        </TR>
        <TR>
';

			t_purposeOID := '';
			FOR l_record IN (
						SELECT trustsrc.TRUST_CONTEXT_ID,
								trustsrc.PURPOSE,
								trustsrc.PURPOSE_OID,
								(ctp.CA_ID IS NOT NULL) HAS_TRUST,
								(ap.PURPOSE IS NOT NULL) IS_APPLICABLE,
								ctp.IS_TIME_VALID,
								ctp.SHORTEST_CHAIN,
								ctp.ALL_CHAINS_REVOKED_VIA_ONECRL,
								ctp.ALL_CHAINS_REVOKED_VIA_CRLSET,
								ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL,
								ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED
							FROM (SELECT tc.DISPLAY_ORDER CTX_DISPLAY_ORDER,
											tc.ID TRUST_CONTEXT_ID,
											tp.ID TRUST_PURPOSE_ID,
											tp.DISPLAY_ORDER,
											tp.PURPOSE,
											tp.PURPOSE_OID
										FROM trust_purpose tp, trust_context tc
										WHERE tp.PURPOSE != 'EV Server Authentication'
									UNION
									SELECT tc.DISPLAY_ORDER CTX_DISPLAY_ORDER,
											tc.ID TRUST_CONTEXT_ID,
											tp.ID TRUST_PURPOSE_ID,
											tp.DISPLAY_ORDER,
											tp.PURPOSE,
											tp.PURPOSE_OID
										FROM ca_trust_purpose ctp_ev, trust_purpose tp, trust_context tc
										WHERE ctp_ev.CA_ID = t_caID
											AND ctp_ev.TRUST_PURPOSE_ID = tp.ID
											AND tp.PURPOSE = 'EV Server Authentication'
										GROUP BY tc.CTX, tc.ID, tp.ID, tp.DISPLAY_ORDER, tp.PURPOSE, tp.PURPOSE_OID
									) trustsrc
								LEFT OUTER JOIN ca_trust_purpose ctp ON (
									ctp.CA_ID = t_caID
									AND trustsrc.TRUST_CONTEXT_ID = ctp.TRUST_CONTEXT_ID
									AND trustsrc.TRUST_PURPOSE_ID = ctp.TRUST_PURPOSE_ID
								)
								LEFT OUTER JOIN applicable_purpose ap ON (
									trustsrc.TRUST_CONTEXT_ID = ap.TRUST_CONTEXT_ID
									AND trustsrc.PURPOSE = ap.PURPOSE
								)
							ORDER BY trustsrc.DISPLAY_ORDER, trustsrc.PURPOSE_OID, trustsrc.CTX_DISPLAY_ORDER
					) LOOP
				IF t_purposeOID != l_record.PURPOSE_OID THEN
					t_purposeOID := l_record.PURPOSE_OID;
					t_text := t_text ||
'        </TR>
        <TR>
          <TD>' || l_record.PURPOSE;
					IF l_record.PURPOSE = 'EV Server Authentication' THEN
						t_text := t_text || ' (' || l_record.PURPOSE_OID || ')';
					END IF;
					t_text := t_text || '</TD>
';
				END IF;
				IF (l_record.TRUST_CONTEXT_ID = 6) AND (l_record.IS_APPLICABLE) THEN
					SELECT true
						INTO l_record.ALL_CHAINS_REVOKED_VIA_CRLSET
						FROM ca_trust_purpose ctp
						WHERE ctp.CA_ID = t_caID
							AND ctp.ALL_CHAINS_REVOKED_VIA_CRLSET
						LIMIT 1;
				END IF;
				t_text := t_text ||
'          <TD style="text-align:center"><FONT color=#';
				IF NOT l_record.IS_APPLICABLE THEN
					t_text := t_text || 'CCCCCC>n/a';
					l_record.SHORTEST_CHAIN := NULL;
				ELSIF l_record.ALL_CHAINS_REVOKED_VIA_ONECRL AND (l_record.TRUST_CONTEXT_ID = 5) THEN
					t_text := t_text || 'CC0000 style="font-weight:bold">Revoked</FONT><BR><FONT style="font-size:8pt;color:#CC0000">via OneCRL';
				ELSIF l_record.ALL_CHAINS_REVOKED_VIA_CRLSET AND (l_record.TRUST_CONTEXT_ID = 6) THEN
					t_text := t_text || 'CC0000 style="font-weight:bold">Revoked</FONT> <FONT style="font-size:8pt;color:#CC0000">via<BR>CRLSet / Blacklist';
				ELSIF l_record.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL AND (l_record.TRUST_CONTEXT_ID = 1) THEN
					t_text := t_text || 'CC0000 style="font-weight:bold">Revoked</FONT> <FONT style="font-size:8pt;color:#CC0000">via<BR>disallowedcert.stl';
				ELSIF (l_record.PURPOSE = 'Server Authentication') AND (l_record.TRUST_CONTEXT_ID = 6) THEN
					t_text := t_text || '888888>Defer to OS';
				ELSIF NOT l_record.HAS_TRUST THEN
					t_text := t_text || '888888>No';
					l_record.SHORTEST_CHAIN := NULL;
				ELSIF NOT l_record.IS_TIME_VALID THEN
					t_text := t_text || '888888>Expired';
				ELSIF l_record.ALL_CHAINS_TECHNICALLY_CONSTRAINED THEN
					t_text := t_text || '00CC00>Constrained';
				ELSE
					t_text := t_text || '00CC00>Valid';
				END IF;
				IF l_record.SHORTEST_CHAIN IS NOT NULL THEN
					t_text := t_text || ' <SPAN style="vertical-align:super;font-size:70%;color:#33A8FF">' || l_record.SHORTEST_CHAIN || '</SPAN>';
				END IF;
				t_text := t_text || '</FONT></TD>
';
			END LOOP;

			t_output := t_output || t_text ||
'        </TR>
      </TABLE>
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
					t_text := t_text || '<A href="?caid=' || l_record.ISSUER_CA_ID::text || t_temp || '">'
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
					t_text := t_text || '<A href="?caid=' || l_record.CA_ID::text || t_temp || '">'
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
    <TD>' || '<A href="?caid=' || l_record.ID::text || coalesce(t_excludeExpired, '') || '">'
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
				'Subject Key Identifier',
				'SHA-1(SubjectPublicKeyInfo)',
				'SHA-256(SubjectPublicKeyInfo)',
				'SHA-1(Subject)',
				'Identity',
				'Common Name',
				'Email Address',
				'Organizational Unit Name',
				'Organization Name',
				'Domain Name',
				'Email Address (SAN)',
				'IP Address',
				'CA/B Forum lint',
				'X.509 lint',
				'Lint'
			) THEN
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
			IF t_caID IS NOT NULL THEN
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

		IF t_outputType = 'html' THEN
			t_output := t_output ||
'  <SPAN class="whiteongrey">Identity Search</SPAN>
';

			IF t_caID IS NULL THEN
				t_temp := urlEncode(t_cmd) || '=' || urlEncode(t_value) || coalesce(t_excludeExpired, '')
							|| coalesce(t_excludeCAsString, '') || t_minNotBeforeString;
				t_output := t_output ||
'  <SPAN style="position:absolute">
    &nbsp; &nbsp; &nbsp; <A href="atom?' || t_temp || '"><IMG src="/feed-icon-28x28.png"></A>
    &nbsp; &nbsp; &nbsp; <A style="font-size:8pt" href="?' || t_temp || '&dir=' || t_direction || '&sort=' || t_sort::text;
				IF t_groupBy = 'none' THEN
					t_output := t_output || '&group=icaid">Group';
				ELSE
					t_output := t_output || '&group=none">Ungroup';
				END IF;
				t_output := t_output || ' by Issuer</A>
  </SPAN>
';
			END IF;

			t_output := t_output ||
'<BR><BR>
<TABLE>
  <TR>
    <TH class="outer">Criteria</TH>
    <TD class="outer">' || html_escape(t_type)
						|| ' ' || html_escape(t_matchType)
						|| ' ''';
			IF lower(t_type) LIKE '%lint' THEN
				SELECT CASE li.SEVERITY
							WHEN 'F' THEN '<SPAN class="fatal">&nbsp;FATAL:'
							WHEN 'E' THEN '<SPAN class="error">&nbsp;ERROR:'
							WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
							WHEN 'N' THEN '<SPAN class="notice">&nbsp;NOTICE:'
							WHEN 'I' THEN '<SPAN>&nbsp;INFO:'
							WHEN 'B' THEN '<SPAN>&nbsp;BUG:'
							ELSE '<SPAN>&nbsp;' || li.SEVERITY || ':'
						END || ' ' || li.ISSUE_TEXT || '&nbsp;</SPAN>'
					INTO t_temp
					FROM lint_issue li
					WHERE li.ID = t_value::integer
						AND li.LINTER = coalesce(t_linter, li.LINTER);
				t_output := t_output || t_temp;
			ELSE
				t_output := t_output || html_escape(t_value);
			END IF;
			t_output := t_output || '''';
			IF t_caID IS NOT NULL THEN
				t_output := t_output || '; Issuer CA ID = ' || t_caID::text;
			END IF;
			IF t_excludeExpired IS NOT NULL THEN
				t_output := t_output || '; Exclude expired certificates';
			END IF;
			t_output := t_output || '</TD>
  </TR>
</TABLE>
<BR>
';

			IF lower(t_type) LIKE '%lint' THEN
				t_output := t_output ||
'For certificates with <B>notBefore >= ' || to_char(t_minNotBefore, 'YYYY-MM-DD') || '</B>:
<BR><BR>
';
				t_opt := '&opt=' || t_linters;
			ELSE
				t_opt := '';
			END IF;
		END IF;

		-- Search for (potentially) multiple certificates.
		IF t_caID IS NOT NULL THEN
			-- Show all of the certs for 1 identity issued by 1 CA.
			t_query := 'SELECT c.ID, x509_subjectName(c.CERTIFICATE) SUBJECT_NAME,' || chr(10) ||
						'		x509_notBefore(c.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
						'		x509_notAfter(c.CERTIFICATE) NOT_AFTER,' || chr(10) ||
						'		c.ISSUER_CA_ID' || chr(10) ||
						'	FROM certificate c' || chr(10);
			IF t_type IN (
						'Serial Number', 'Subject Key Identifier',
						'SHA-1(SubjectPublicKeyInfo)', 'SHA-256(SubjectPublicKeyInfo)', 'SHA-1(Subject)'
					) THEN
				IF t_type = 'Serial Number' THEN
					t_query := t_query ||
						'	WHERE x509_serialNumber(c.CERTIFICATE) = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'Subject Key Identifier' THEN
					t_query := t_query ||
						'	WHERE x509_subjectKeyIdentifier(c.CERTIFICATE) = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
					t_query := t_query ||
						'	WHERE digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-256(SubjectPublicKeyInfo)' THEN
					t_query := t_query ||
						'	WHERE digest(x509_publickey(c.CERTIFICATE), ''sha256'') = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(Subject)' THEN
					t_query := t_query ||
						'	WHERE digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				END IF;
				t_query := t_query ||
						'		AND c.ISSUER_CA_ID = $1' || chr(10);
			ELSIF (t_type = 'Identity') AND (t_value = '%') THEN
				t_query := t_query ||
						'	WHERE c.ISSUER_CA_ID = $1' || chr(10);
			ELSIF lower(t_type) LIKE '%lint' THEN
				t_query := t_query ||
						'		, lint_cert_issue lci, lint_issue li' || chr(10) ||
						'	WHERE c.ISSUER_CA_ID = $1::integer' || chr(10) ||
						'		AND c.ID = lci.CERTIFICATE_ID' || chr(10) ||
						'		AND lci.ISSUER_CA_ID = $1::integer' || chr(10) ||
						'		AND lci.NOT_BEFORE >= $3' || chr(10) ||
						'		AND lci.LINT_ISSUE_ID = $2::integer' || chr(10) ||
						'		AND lci.LINT_ISSUE_ID = li.ID' || chr(10);
				IF t_linter IS NOT NULL THEN
					t_query := t_query ||
						'		AND li.LINTER = ''' || t_linter || '''' || chr(10);
				END IF;
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
			IF t_excludeExpired IS NOT NULL THEN
				t_query := t_query ||
						'		AND x509_notAfter(c.CERTIFICATE) > statement_timestamp()' || chr(10);
			END IF;
			IF lower(t_type) LIKE '%lint' THEN
				t_query := t_query ||
						'	GROUP BY c.ID, c.ISSUER_CA_ID, SUBJECT_NAME, NOT_BEFORE, NOT_AFTER' || chr(10);
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
							USING t_caID, t_value, t_minNotBefore LOOP
				t_count := t_count + 1;
				t_text := t_text ||
'  <TR>
    <TD style="text-align:center"><A href="?id=' || l_record.ID::text;
				IF lower(t_type) LIKE '%lint' THEN
					t_text := t_text || '&opt=' || t_linters;
				END IF;
				t_text := t_text || '">' || l_record.ID::text || '</A></TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || '</TD>
    <TD style="white-space:nowrap">' || to_char(l_record.NOT_AFTER, 'YYYY-MM-DD') || '</TD>
    <TD>' || html_escape(l_record.SUBJECT_NAME) || '</TD>
  </TR>
';
			END LOOP;

			IF t_pageNo IS NOT NULL THEN
				IF (t_value = '%') AND (t_excludeExpired IS NULL) THEN
					SELECT ca.NO_OF_CERTS_ISSUED
						INTO t_count
						FROM ca
						WHERE ca.ID = t_caID;
				ELSE
					t_temp := 'SELECT count(*) FROM (' || chr(10) || substring(t_query from '^.*	ORDER BY');
					t_temp := substr(t_temp, 1, length(t_temp) - length('	ORDER BY')) || ') sub';
					EXECUTE t_temp INTO t_count USING t_caID, t_value, t_minNotBefore;
				END IF;
			END IF;

			SELECT ca.NAME
				INTO t_temp
				FROM ca
				WHERE ca.ID = t_caID;
			t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Issuer Name</TH>
    <TD class="outer"><A href="?caid=' || t_caID::text || coalesce(t_excludeExpired, '') || t_opt || '">'
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
									'&iCAID=' || t_caID::text || coalesce(t_excludeExpired, '') ||
									'&p=' || (t_pageNo - 1)::text ||
									'&n=' || t_resultsPerPage::text || '">Previous</A> &nbsp; ';
					END IF;
					t_output := t_output || '<B>' ||
								(((t_pageNo - 1) * t_resultsPerPage) + 1)::integer || '</B> to <B>' ||
								least(t_pageNo * t_resultsPerPage, t_count)::integer || '</B>';
					IF (t_pageNo * t_resultsPerPage) < t_count THEN
						t_output := t_output || ' &nbsp; <A style="font-size:8pt" href="?' ||
									urlEncode(t_type) || '=' || urlEncode(t_value) ||
									'&iCAID=' || t_caID::text || coalesce(t_excludeExpired, '') ||
									'&p=' || (t_pageNo + 1)::text ||
									'&n=' || t_resultsPerPage::text || '">Next</A>';
					END IF;
					t_output := t_output || '</TD></TR>
';
				END IF;
				t_output := t_output ||
'  <TR>
    <TH style="white-space:nowrap">crt.sh ID</TH>
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

			t_select := 	'SELECT __issuer_ca_id_table__.ISSUER_CA_ID,' || chr(10) ||
							'        ca.NAME ISSUER_NAME,' || chr(10) ||
							'        __name_value__ NAME_VALUE,' || chr(10) ||
							'        min(__cert_id_field__) MIN_CERT_ID,' || chr(10);
			t_from := 		'    FROM ca';
			t_where :=		'    WHERE __issuer_ca_id_table__.ISSUER_CA_ID = ca.ID';
			IF coalesce(t_groupBy, '') = 'none' THEN
				t_select := t_select ||
							'        min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP,' || chr(10) ||
							'        x509_notBefore(c.CERTIFICATE) NOT_BEFORE';
				t_from := t_from || ',' || chr(10) ||
							'        ct_log_entry ctle';
				t_where := t_where || chr(10) ||
							'        AND __ctle_cert_id__ = ctle.CERTIFICATE_ID';
				t_joinToCTLogEntry := 'c.ID';

				t_query :=	'    GROUP BY c.ID, __issuer_ca_id_table__.ISSUER_CA_ID, ISSUER_NAME, NAME_VALUE' || chr(10) ||
							'    ORDER BY ';
				IF t_sort = 0 THEN
					t_query := t_query || 'MIN_CERT_ID ' || t_orderBy;
				ELSIF t_sort = 1 THEN
					t_query := t_query || 'MIN_ENTRY_TIMESTAMP ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				ELSIF t_sort = 2 THEN
					t_query := t_query || 'NOT_BEFORE ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				ELSE
					t_query := t_query || 'ISSUER_NAME ' || t_orderBy || ', NOT_BEFORE ' || t_orderBy || ', NAME_VALUE';
				END IF;
			ELSE
				-- Group certs for the same identity issued by the same CA.
				t_select := t_select ||
							'        count(DISTINCT __cert_id_field__) NUM_CERTS';

				t_query :=	'    GROUP BY __issuer_ca_id_table__.ISSUER_CA_ID, ISSUER_NAME, NAME_VALUE' || chr(10) ||
							'    ORDER BY ';
				IF t_sort = 3 THEN
					t_query := t_query || 'ISSUER_NAME ' || t_orderBy || ', NAME_VALUE, NUM_CERTS';
				ELSE
					t_query := t_query || 'NUM_CERTS ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				END IF;
			END IF;

			IF t_type = 'CT Entry ID' THEN
				IF coalesce(t_groupBy, '') != 'none' THEN
					t_from := t_from || ',' || chr(10) ||
							'        ct_log_entry ctle';
				END IF;
				t_from := t_from || ',' || chr(10) ||
							'        ct_log ctl';
				t_issuerCAID_table := 'c';
				t_nameValue := 'ctl.NAME';
				t_certID_field := 'c.ID';
				t_joinToCertificate_table := 'ctle';
				t_where := t_where || chr(10) ||
							'        AND ctle.ENTRY_ID = $1::integer' || chr(10) ||
							'        AND ctle.CT_LOG_ID = ctl.ID';
			ELSIF t_type = 'Serial Number' THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(x509_serialNumber(c.CERTIFICATE), ''hex'')';
				t_certID_field := 'c.ID';
				t_where := t_where || chr(10) ||
							'        AND x509_serialNumber(c.CERTIFICATE) = decode($1, ''hex'')';
			ELSIF t_type = 'Subject Key Identifier' THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(x509_subjectKeyIdentifier(c.CERTIFICATE), ''hex'')';
				t_certID_field := 'c.ID';
				t_where := t_where || chr(10) ||
							'        AND x509_subjectKeyIdentifier(c.CERTIFICATE) = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_publickey(c.CERTIFICATE), ''sha1''), ''hex'')';
				t_certID_field := 'c.ID';
				t_where := t_where || chr(10) ||
							'        AND digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-256(SubjectPublicKeyInfo)' THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_publickey(c.CERTIFICATE), ''sha256''), ''hex'')';
				t_certID_field := 'c.ID';
				t_where := t_where || chr(10) ||
							'        AND digest(x509_publickey(c.CERTIFICATE), ''sha256'') = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-1(Subject)' THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_name(c.CERTIFICATE), ''sha1''), ''hex'')';
				t_certID_field := 'c.ID';
				t_where := t_where || chr(10) ||
							'        AND digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')';
			ELSIF lower(t_type) LIKE '%lint' THEN
				t_from := t_from || ',' || chr(10) ||
							'        lint_issue li,' || chr(10) ||
							'        lint_cert_issue lci';
				t_issuerCAID_table := 'lci';
				t_nameValue := 'lci.LINT_ISSUE_ID::text';
				IF coalesce(t_groupBy, '') = 'none' THEN
					t_certID_field := 'c.ID';
					t_joinToCertificate_table := 'lci';
				ELSE
					t_certID_field := 'lci.CERTIFICATE_ID';
					IF t_excludeExpired IS NOT NULL THEN
						t_joinToCertificate_table := 'lci';
					END IF;
				END IF;
				t_where := t_where || chr(10) ||
							'        AND lci.LINT_ISSUE_ID = $1::integer' || chr(10) ||
							'        AND lci.NOT_BEFORE >= $2' || chr(10) ||
							'        AND lci.LINT_ISSUE_ID = li.ID' || chr(10) ||
							'        AND ca.LINTING_APPLIES';
				IF t_linter IS NOT NULL THEN
					t_where := t_where || chr(10) ||
							'        AND li.LINTER = ''' || t_linter || '''';
				END IF;
			ELSE
				t_from := t_from || ',' || chr(10) ||
							'        certificate_identity ci';
				t_issuerCAID_table := 'ci';
				t_nameValue := 'ci.NAME_VALUE';
				IF coalesce(t_groupBy, '') = 'none' THEN
					t_certID_field := 'c.ID';
					t_joinToCertificate_table := 'ci';
				ELSE
					t_certID_field := 'ci.CERTIFICATE_ID';
					IF t_excludeExpired IS NOT NULL THEN
						t_joinToCertificate_table := 'ci';
					END IF;
				END IF;
				IF t_useReverseIndex THEN
					t_where := t_where || chr(10) ||
							'        AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))';
				ELSE
					t_where := t_where || chr(10) ||
							'        AND lower(ci.NAME_VALUE) LIKE lower($1)';
				END IF;
				IF t_type != 'Identity' THEN
					t_where := t_where || chr(10) ||
							'        AND ci.NAME_TYPE = ' || quote_literal(t_nameType);
				END IF;
			END IF;

			IF t_joinToCertificate_table IS NOT NULL THEN
				t_from := t_from || ',' || chr(10) ||
							'        certificate c';
				t_where := t_where || chr(10) ||
							'        AND ' || t_joinToCertificate_table || '.CERTIFICATE_ID = c.ID';
			END IF;

			IF t_excludeExpired IS NOT NULL THEN
				t_where := t_where || chr(10) ||
							'        AND x509_notAfter(c.CERTIFICATE) > statement_timestamp()';
			END IF;
			IF t_excludeCAsString IS NOT NULL THEN
				t_where := t_where || chr(10) ||
							'        AND ' || t_issuerCAID_table || '.ISSUER_CA_ID NOT IN (' || array_to_string(t_excludeCAs, ',') || ')';
			END IF;

			t_query := t_select || chr(10)
					|| t_from || chr(10)
					|| t_where || chr(10)
					|| t_query;

			t_query := replace(t_query, '__issuer_ca_id_table__', t_issuerCAID_table);
			t_query := replace(t_query, '__name_value__', t_nameValue);
			t_query := replace(t_query, '__cert_id_field__', t_certID_field);
			IF t_joinToCTLogEntry IS NOT NULL THEN
				t_query := replace(t_query, '__ctle_cert_id__', t_joinToCTLogEntry);
			END IF;

			t_showIdentity := (position('%' IN t_value) > 0) OR (t_type = 'CT Entry ID');

			t_text := '';
			t_summary := '';
			FOR l_record IN EXECUTE t_query
							USING t_value, t_minNotBefore LOOP
				IF t_outputType = 'atom' THEN
					IF coalesce(t_certificateID, -l_record.MIN_CERT_ID) != l_record.MIN_CERT_ID THEN
						IF lower(t_type) NOT LIKE '%lint' THEN
							t_text := replace(t_text, '__entry_summary__', t_summary);
						END IF;
						t_summary := l_record.NAME_VALUE;
						t_certificateID := l_record.MIN_CERT_ID;
					ELSE
						t_summary := t_summary || ' &amp;nbsp; ' || l_record.NAME_VALUE;
						CONTINUE;
					END IF;

					SELECT to_char(x509_notAfter(c.CERTIFICATE), 'YYYY-MM-DD')
							|| '; Serial number ' || encode(x509_serialNumber(c.CERTIFICATE), 'hex'),
							c.CERTIFICATE
						INTO t_temp,
							t_certificate
						FROM certificate c
						WHERE c.ID = l_record.MIN_CERT_ID;
					t_b64Certificate := replace(encode(t_certificate, 'base64'), chr(10), '');
					t_feedUpdated := greatest(t_feedUpdated, l_record.MIN_ENTRY_TIMESTAMP);
					t_text := t_text ||
'  <entry>
    <id>https://crt.sh/?id=' || l_record.MIN_CERT_ID || '#' || t_cmd || ';' || t_value || '</id>
    <link rel="alternate" type="text/html" href="https://crt.sh/?id=' || l_record.MIN_CERT_ID || '"/>
    <summary type="html">__entry_summary__&lt;br&gt;&lt;br&gt;&lt;div style="font:8pt monospace"&gt;-----BEGIN CERTIFICATE-----';
					WHILE length(t_b64Certificate) > 0 LOOP
						t_text := t_text || '&lt;br&gt;' || substring(
							t_b64Certificate from 1 for 64
						);
						t_b64Certificate := substring(t_b64Certificate from 65);
					END LOOP;
					t_text := t_text ||
'&lt;br&gt;-----END CERTIFICATE-----&lt;/div&gt;
    </summary>
    <title>[';
					IF x509_print(t_certificate) LIKE '%CT Precertificate Poison%' THEN
						t_text := t_text || 'Precertificate';
					ELSE
						t_text := t_text || 'Certificate';
					END IF;
					t_text := t_text ||
'] Issued by ' || get_ca_name_attribute(l_record.ISSUER_CA_ID)
			|| '; Valid from ' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || ' to '
			|| t_temp || '</title>
    <published>' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</published>
    <updated>' || to_char(l_record.MIN_ENTRY_TIMESTAMP, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</updated>
  </entry>
';
				ELSIF t_outputType = 'json' THEN
					t_output := t_output || row_to_json(l_record, FALSE);
				ELSIF t_outputType = 'html' THEN
					t_text := t_text ||
'  <TR>
    <TD style="text-align:center">';
					IF coalesce(t_groupBy, '') = 'none' THEN
						t_text := t_text || '<A href="?id=' || l_record.MIN_CERT_ID::text || t_opt || '">' || l_record.MIN_CERT_ID::text || '</A></TD>
    <TD style="text-align:center">' || to_char(l_record.MIN_ENTRY_TIMESTAMP, 'YYYY-MM-DD') || '</TD>
    <TD style="text-align:center">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD');
					ELSIF (l_record.NUM_CERTS = 1)
							AND (l_record.MIN_CERT_ID IS NOT NULL) THEN
						t_text := t_text || '<A href="?id=' || l_record.MIN_CERT_ID::text || t_opt || '">'
															|| l_record.NUM_CERTS::text || '</A>';
					ELSIF (l_record.ISSUER_CA_ID IS NOT NULL)
							AND (l_record.MIN_CERT_ID IS NOT NULL) THEN
						t_text := t_text || '<A href="?' || t_paramName || '=' || urlEncode(l_record.NAME_VALUE)
												|| '&iCAID=' || l_record.ISSUER_CA_ID::text || t_minNotBeforeString
												|| coalesce(t_excludeExpired, '') || t_opt || '">'
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
						t_text := t_text || '<A style="white-space:normal" href="?caid=' || l_record.ISSUER_CA_ID::text || t_opt || '">'
									|| coalesce(html_escape(l_record.ISSUER_NAME), '&nbsp;')
									|| '</A>';
					ELSE
						t_text := t_text || coalesce(html_escape(l_record.ISSUER_NAME), '?');
					END IF;
					IF lower(t_type) LIKE '%lint' THEN
						SELECT md.INCLUDED_CERTIFICATE_OWNER
							INTO t_temp
							FROM ca_certificate cac, mozilla_disclosure md
							WHERE cac.CA_ID = l_record.ISSUER_CA_ID
								AND cac.CERTIFICATE_ID = md.CERTIFICATE_ID
							GROUP BY md.INCLUDED_CERTIFICATE_OWNER
							ORDER BY count(*) DESC
							LIMIT 1;
						t_text := t_text || '</TD>
    <TD>' || coalesce(t_temp, '&nbsp;');
					END IF;
					t_text := t_text || '</TD>
  </TR>
';
				END IF;
			END LOOP;

			t_temp := replace(
				urlEncode(t_cmd) || '=' || urlEncode(t_value) || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, ''),
				'&', '&amp;'
			);
			IF t_outputType = 'atom' THEN
				t_output :=
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::integer || '
Content-Type: application/atom+xml
[END_HEADERS]
<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en">
  <author>
    <name>crt.sh</name>
    <uri>https://crt.sh/</uri>
  </author>
  <icon>https://crt.sh/favicon.ico</icon>
  <id>https://crt.sh/?' || t_temp || '</id>
  <link rel="self" type="application/atom+xml" href="https://crt.sh/atom?' || t_temp || '"/>
  <link rel="via" type="text/html" href="https://crt.sh/"/>
  <title>';
			IF lower(t_type) LIKE '%lint' THEN
				SELECT '[' || li.LINTER || '] ' || li.ISSUE_TEXT
					INTO t_summary
					FROM lint_issue li
					WHERE li.ID = t_value::integer;
				t_output := t_output || t_summary;
			ELSE
				t_output := t_output || t_cmd || '=' || t_value;
			END IF;
			IF t_excludeExpired IS NOT NULL THEN
				t_output := t_output || '; ' || substring(t_excludeExpired from 2);
			END IF;
			IF t_excludeCAsString IS NOT NULL THEN
				t_output := t_output || '; ' || substring(t_excludeCAsString from 2);
			END IF;
			IF coalesce(t_minNotBeforeString, '') != '' THEN
				t_output := t_output || '; ' || substring(t_minNotBeforeString from 2);
			END IF;
			t_output := t_output || '</title>
  <updated>' || to_char(coalesce(t_feedUpdated, statement_timestamp()), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</updated>
' || replace(t_text, '__entry_summary__', t_summary) ||
'</feed>';
			ELSIF t_outputType = 'html' THEN
				t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Certificates</TH>
    <TD class="outer">';
				IF t_text != '' THEN
					t_output := t_output || '
<TABLE>
  <TR>
';
					IF coalesce(t_groupBy, '') = 'none' THEN
						t_output := t_output ||
'    <TH>
      <A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=0' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">crt.sh ID</A>
';
						IF t_sort = 0 THEN
							t_output := t_output || ' ' || t_dirSymbol;
						END IF;
						t_output := t_output ||
'    </TH>
    <TH style="white-space:nowrap">
      &nbsp;<A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=1' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">Logged At</A>&nbsp;
';
						IF t_sort = 1 THEN
							t_output := t_output || ' ' || t_dirSymbol;
						END IF;
						t_output := t_output ||
'    </TH>
    <TH style="white-space:nowrap"><A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=2' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">Not Before</A>
';
						IF t_sort = 2 THEN
							t_output := t_output || ' ' || t_dirSymbol;
						END IF;
						t_output := t_output ||
'    </TH>
';
					ELSE
						t_output := t_output ||
'    <TH>
      <A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=1' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">#</A>
';
						IF t_sort = 1 THEN
							t_output := t_output || ' ' || t_dirSymbol;
						END IF;
						t_output := t_output ||
'    </TH>
';
					END IF;
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
'    <TH>
      <A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=3' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">Issuer Name</A>
';
					IF t_sort = 3 THEN
						t_output := t_output || ' ' || t_dirSymbol;
					END IF;
					t_output := t_output ||
'    </TH>
';
					IF lower(t_type) LIKE '%lint' THEN
						t_output := t_output ||
'    <TH>Root Owner (Mozilla)</TH>
';
					END IF;
					t_output := t_output ||
'  </TR>
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
		END IF;

	ELSIF lower(t_type) LIKE '%lint: summary' THEN
		IF t_sort NOT BETWEEN 1 AND 18 THEN
			t_sort := 1;
		END IF;

		t_issuerO := get_parameter('issuerO', paramNames, paramValues);
		t_issuerOParameter := coalesce(t_issuerO, '');
		IF t_issuerOParameter != '' THEN
			t_issuerOParameter := '&issuerO=' || t_issuerOParameter;
		END IF;

		IF t_outputType = 'html' THEN
			t_output := t_output ||
'  <SPAN class="whiteongrey">' || t_type || '</SPAN>
';
		END IF;

		IF t_value != '1 week' THEN
			t_output := t_output ||
'  <BR><BR>Sorry, only "1 week" statistics are currently supported.
';
		ELSIF t_groupBy NOT IN ('', 'IssuerO') THEN
			t_output := t_output ||
'  <BR><BR>Sorry, "IssuerO" is the only currently supported value for "group".
';
		ELSE
			IF t_outputType = 'html' THEN
				t_output := t_output ||
'  <SPAN style="position:absolute">
    &nbsp; &nbsp; &nbsp; <A style="font-size:8pt;vertical-align:sub" href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_direction || '&sort=' || t_sort::text || t_issuerOParameter;
				IF t_groupBy != 'IssuerO' THEN
					t_output := t_output || '&group=IssuerO">Group';
				ELSE
					t_output := t_output || '">Ungroup';
				END IF;
				t_output := t_output || ' by "Issuer O"</A>
';
				IF t_issuerO IS NOT NULL THEN
					t_output := t_output || ' &nbsp; &nbsp; <A style="font-size:8pt;vertical-align:sub" href="?' || t_cmd || '=' || urlEncode(t_value)
										|| '&dir=' || t_direction || '&sort=' || t_sort::text || t_groupByParameter || '">Show all "Issuer O"s</A>
';
				END IF;
				t_output := t_output ||
'  </SPAN>
  <BR><BR>
  For certificates with <B>notBefore >= ' || to_char(date_trunc('day', statement_timestamp() - interval '1 week'), 'YYYY-MM-DD') || '</B>';
				IF t_issuerO IS NOT NULL THEN
					t_output := t_output || ' and <B>"Issuer O" LIKE ''' || t_issuerO || '''</B>';
				END IF;
				t_output := t_output || ':
  <BR><BR>
  <TABLE class="lint">
    <TR>
      <TH rowspan="2"><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=1' || t_groupByParameter || t_issuerOParameter || '">Issuer O</A>';
				IF t_sort = 1 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				IF t_groupBy != 'IssuerO' THEN
					t_output := t_output || '</TH>
      <TH rowspan="2"><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=2' || t_groupByParameter || t_issuerOParameter || '">Issuer CN, OU or O</A>';
					IF t_sort = 2 THEN
						t_output := t_output || ' ' || t_dirSymbol;
					END IF;
				END IF;
				t_output := t_output || '</TH>
      <TH rowspan="2"><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=3' || t_groupByParameter || t_issuerOParameter || '"># Certs<BR>Issued</A>';
				IF t_sort = 3 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH colspan="3"><A title="These errors are fatal to the checks and prevent most further checks from being executed.  These are extremely bad errors."><SPAN class="fatal">&nbsp;FATAL&nbsp;</SPAN></A></TH>
      <TH colspan="3"><A title="These are issues where the certificate is not compliant with the standard."><SPAN class="error">&nbsp;ERROR&nbsp;</SPAN></A></TH>
      <TH colspan="3"><A title="These are issues where a standard recommends differently but the standard uses terms such as ''SHOULD'' or ''MAY''."><SPAN class="warning">&nbsp;WARNING&nbsp;</SPAN></A></TH>
      <TH colspan="3"><A title="These are items known to cause issues with one or more implementations of certificate processing but are not errors according to the standard."><SPAN class="notice">&nbsp;NOTICE&nbsp;</SPAN></A></TH>
      <TH colspan="3"><A title="FATAL + ERROR + WARNING + NOTICE">ALL</A></TH>
    </TR>
    <TR>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=4' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 4 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=5' || t_groupByParameter || t_issuerOParameter || '">%</A>';
				IF t_sort = 5 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=6' || t_groupByParameter || t_issuerOParameter || '"># Issues</A>';
				IF t_sort = 6 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=7' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 7 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=8' || t_groupByParameter || t_issuerOParameter || '">%</A>';
				IF t_sort = 8 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=9' || t_groupByParameter || t_issuerOParameter || '"># Issues</A>';
				IF t_sort = 9 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=10' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 10 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=11' || t_groupByParameter || t_issuerOParameter || '">%</A>';
				IF t_sort = 11 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=12' || t_groupByParameter || t_issuerOParameter || '"># Issues</A>';
				IF t_sort = 12 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=13' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 13 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=14' || t_groupByParameter || t_issuerOParameter || '">%</A>';
				IF t_sort = 14 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=15' || t_groupByParameter || t_issuerOParameter || '"># Issues</A>';
				IF t_sort = 15 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=16' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 16 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=17' || t_groupByParameter || t_issuerOParameter || '">%</A>';
				IF t_sort = 17 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=18' || t_groupByParameter || t_issuerOParameter || '"># Issues</A>';
				IF t_sort = 18 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
    </TR>
';
			END IF;

			IF t_groupBy = 'IssuerO' THEN
				t_query := 'SELECT NULL::integer ISSUER_CA_ID,' || chr(10) ||
							'		(sum(l1s.CERTS_ISSUED))::bigint CERTS_ISSUED,' || chr(10) ||
							'		(sum(l1s.ALL_CERTS))::bigint ALL_CERTS,' || chr(10) ||
							'		(sum(l1s.ALL_ISSUES))::bigint ALL_ISSUES,' || chr(10) ||
							'		((sum(l1s.ALL_CERTS) * 100) / sum(l1s.CERTS_ISSUED))::numeric ALL_PERC,' || chr(10) ||
							'		(sum(l1s.FATAL_CERTS))::bigint FATAL_CERTS,' || chr(10) ||
							'		(sum(l1s.FATAL_ISSUES))::bigint FATAL_ISSUES,' || chr(10) ||
							'		((sum(l1s.FATAL_CERTS) * 100) / sum(l1s.CERTS_ISSUED))::numeric FATAL_PERC,' || chr(10) ||
							'		(sum(l1s.ERROR_CERTS))::bigint ERROR_CERTS,' || chr(10) ||
							'		(sum(l1s.ERROR_ISSUES))::bigint ERROR_ISSUES,' || chr(10) ||
							'		((sum(l1s.ERROR_CERTS) * 100) / sum(l1s.CERTS_ISSUED))::numeric ERROR_PERC,' || chr(10) ||
							'		(sum(l1s.WARNING_CERTS))::bigint WARNING_CERTS,' || chr(10) ||
							'		(sum(l1s.WARNING_ISSUES))::bigint WARNING_ISSUES,' || chr(10) ||
							'		((sum(l1s.WARNING_CERTS) * 100) / sum(l1s.CERTS_ISSUED))::numeric WARNING_PERC,' || chr(10) ||
							'		(sum(l1s.NOTICE_CERTS))::bigint NOTICE_CERTS,' || chr(10) ||
							'		(sum(l1s.NOTICE_ISSUES))::bigint NOTICE_ISSUES,' || chr(10) ||
							'		((sum(l1s.NOTICE_CERTS) * 100) / sum(l1s.CERTS_ISSUED))::numeric NOTICE_PERC,' || chr(10) ||
							'		get_ca_name_attribute(l1s.ISSUER_CA_ID, ''organizationName'') ISSUER_ORGANIZATION_NAME,' || chr(10) ||
							'		NULL ISSUER_FRIENDLY_NAME' || chr(10);
			ELSE
				t_query := 'SELECT l1s.ISSUER_CA_ID::integer,' || chr(10) ||
							'		l1s.CERTS_ISSUED::bigint,' || chr(10) ||
							'		l1s.ALL_CERTS::bigint,' || chr(10) ||
							'		l1s.ALL_ISSUES::bigint,' || chr(10) ||
							'		((l1s.ALL_CERTS * 100) / l1s.CERTS_ISSUED::numeric) ALL_PERC,' || chr(10) ||
							'		l1s.FATAL_CERTS::bigint,' || chr(10) ||
							'		l1s.FATAL_ISSUES::bigint,' || chr(10) ||
							'		((l1s.FATAL_CERTS * 100) / l1s.CERTS_ISSUED::numeric) FATAL_PERC,' || chr(10) ||
							'		l1s.ERROR_CERTS::bigint,' || chr(10) ||
							'		l1s.ERROR_ISSUES::bigint,' || chr(10) ||
							'		((l1s.ERROR_CERTS * 100) / l1s.CERTS_ISSUED::numeric) ERROR_PERC,' || chr(10) ||
							'		l1s.WARNING_CERTS::bigint,' || chr(10) ||
							'		l1s.WARNING_ISSUES::bigint,' || chr(10) ||
							'		((l1s.WARNING_CERTS * 100) / l1s.CERTS_ISSUED::numeric) WARNING_PERC,' || chr(10) ||
							'		l1s.NOTICE_CERTS::bigint,' || chr(10) ||
							'		l1s.NOTICE_ISSUES::bigint,' || chr(10) ||
							'		((l1s.NOTICE_CERTS * 100) / l1s.CERTS_ISSUED::numeric) NOTICE_PERC,' || chr(10) ||
							'		get_ca_name_attribute(l1s.ISSUER_CA_ID, ''organizationName'') ISSUER_ORGANIZATION_NAME,' || chr(10) ||
							'		get_ca_name_attribute(l1s.ISSUER_CA_ID, ''_friendlyName_'') ISSUER_FRIENDLY_NAME' || chr(10);
			END IF;
			t_query := t_query ||
							'	FROM lint_1week_summary l1s' || chr(10) ||
							'	WHERE l1s.LINTER ';
			IF t_linter IS NOT NULL THEN
				t_query := t_query || '= ''' || t_linter || '''' || chr(10);
			ELSE
				t_query := t_query || 'IS NULL' || chr(10);
			END IF;
			IF t_issuerO IS NOT NULL THEN
				t_query := t_query ||
							'		AND get_ca_name_attribute(l1s.ISSUER_CA_ID, ''organizationName'') LIKE $1' || chr(10);
			END IF;
			t_query := t_query || '	';
			IF t_groupBy = 'IssuerO' THEN
				t_query := t_query || '	GROUP BY ISSUER_ORGANIZATION_NAME' || chr(10) ||
							'	';
			END IF;

			IF t_sort = 1 THEN
				t_query := t_query || 'ORDER BY ISSUER_ORGANIZATION_NAME ' || t_orderBy || ', ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 2 THEN
				t_query := t_query || 'ORDER BY ISSUER_FRIENDLY_NAME ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
			ELSIF t_sort = 3 THEN
				t_query := t_query || 'ORDER BY CERTS_ISSUED ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 4 THEN
				t_query := t_query || 'ORDER BY FATAL_CERTS ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 5 THEN
				t_query := t_query || 'ORDER BY FATAL_PERC ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 6 THEN
				t_query := t_query || 'ORDER BY FATAL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 7 THEN
				t_query := t_query || 'ORDER BY ERROR_CERTS ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 8 THEN
				t_query := t_query || 'ORDER BY ERROR_PERC ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 9 THEN
				t_query := t_query || 'ORDER BY ERROR_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 10 THEN
				t_query := t_query || 'ORDER BY WARNING_CERTS ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 11 THEN
				t_query := t_query || 'ORDER BY WARNING_PERC ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 12 THEN
				t_query := t_query || 'ORDER BY WARNING_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 13 THEN
				t_query := t_query || 'ORDER BY NOTICE_CERTS ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 14 THEN
				t_query := t_query || 'ORDER BY NOTICE_PERC ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 15 THEN
				t_query := t_query || 'ORDER BY NOTICE_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 16 THEN
				t_query := t_query || 'ORDER BY ALL_CERTS ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 17 THEN
				t_query := t_query || 'ORDER BY ALL_PERC ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			ELSIF t_sort = 18 THEN
				t_query := t_query || 'ORDER BY ALL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
			END IF;

			FOR l_record IN EXECUTE t_query USING t_issuerO LOOP
				IF t_outputType = 'json' THEN
					t_output := t_output || row_to_json(l_record, FALSE);
				ELSIF t_outputType = 'html' THEN
					t_output := t_output || '
    <TR>
      <TD>';
					IF l_record.ISSUER_ORGANIZATION_NAME IS NOT NULL THEN
						t_output := t_output || '<A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_direction
											|| '&sort=' || t_sort::text || t_groupByParameter
											|| '&issuerO=' || urlEncode(l_record.ISSUER_ORGANIZATION_NAME) || '">'
											|| l_record.ISSUER_ORGANIZATION_NAME || '</A>';
					ELSE
						t_output := t_output || '&nbsp;';
					END IF;
					t_output := t_output || '</TD>
';
					IF t_groupBy != 'IssuerO' THEN
						t_output := t_output ||
'      <TD><A href="?caid=' || l_record.ISSUER_CA_ID::text || '&opt=' || t_linters || '">' || coalesce(l_record.ISSUER_FRIENDLY_NAME, '&nbsp;') || '</A></TD>
';
					END IF;
					t_output := t_output ||
'      <TD>' || l_record.CERTS_ISSUED::text || '</TD>
      <TD>' || l_record.FATAL_CERTS::text || '</TD>
      <TD>' || replace(round(l_record.FATAL_PERC, 2)::text, '.00', '') || '</TD>
      <TD>' || l_record.FATAL_ISSUES::text || '</TD>
      <TD>' || l_record.ERROR_CERTS::text || '</TD>
      <TD>' || replace(round(l_record.ERROR_PERC, 2)::text, '.00', '') || '</TD>
      <TD>' || l_record.ERROR_ISSUES::text || '</TD>
      <TD>' || l_record.WARNING_CERTS::text || '</TD>
      <TD>' || replace(round(l_record.WARNING_PERC, 2)::text, '.00', '') || '</TD>
      <TD>' || l_record.WARNING_ISSUES::text || '</TD>
      <TD>' || l_record.NOTICE_CERTS::text || '</TD>
      <TD>' || replace(round(l_record.NOTICE_PERC, 2)::text, '.00', '') || '</TD>
      <TD>' || l_record.NOTICE_ISSUES::text || '</TD>
      <TD>' || l_record.ALL_CERTS::text || '</TD>
      <TD>' || replace(round(l_record.ALL_PERC, 2)::text, '.00', '') || '</TD>
      <TD>' || l_record.ALL_ISSUES::text || '</TD>
    </TR>
';
				END IF;
			END LOOP;

			IF t_outputType = 'html' THEN
				t_output := t_output ||
'  </TABLE>
';
			END IF;
		END IF;

	ELSIF lower(t_type) LIKE '%lint: issues' THEN
		IF t_sort NOT BETWEEN 1 AND 3 THEN
			t_sort := 1;
		END IF;

		t_temp := get_parameter('exclude', paramNames, paramValues);
		IF lower(coalesce(',' || t_temp || ',', 'nothing')) LIKE ',affected_certs,' THEN
			t_excludeAffectedCerts := '&exclude=affected_certs';
		END IF;

		IF t_outputType = 'html' THEN
			t_output := t_output ||
'  <SPAN class="whiteongrey">' || t_type || '</SPAN>
  <BR><BR>
  For certificates with <B>notBefore >= ' || to_char(t_minNotBefore, 'YYYY-MM-DD') || '</B>:
  <BR><BR>
  <TABLE class="lint">
    <TR>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=1' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '">Severity</A>';
			IF t_sort = 1 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=2' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '">Issue</A>';
			IF t_sort = 2 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
      <TH><A href="?' || t_cmd || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=3' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '"># Affected Certs</A>';
			IF t_sort = 3 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
    </TR>
';
		END IF;

		t_query := 'SELECT li.ID, li.ISSUE_TEXT,';
		IF t_excludeAffectedCerts IS NULL THEN
			t_query := t_query || ' count(DISTINCT lci.CERTIFICATE_ID) NUM_CERTS,';
		ELSE
			t_query := t_query || ' -1::bigint NUM_CERTS,';
		END IF;
		t_query := t_query || chr(10) ||
					'		CASE li.SEVERITY' || chr(10) ||
					'			WHEN ''F'' THEN 1' || chr(10) ||
					'			WHEN ''E'' THEN 2' || chr(10) ||
					'			WHEN ''W'' THEN 3' || chr(10) ||
					'			WHEN ''N'' THEN 4' || chr(10) ||
					'			WHEN ''I'' THEN 5' || chr(10) ||
					'			WHEN ''B'' THEN 6' || chr(10) ||
					'			ELSE 7' || chr(10) ||
					'		END ISSUE_TYPE,' || chr(10) ||
					'		CASE li.SEVERITY' || chr(10) ||
					'			WHEN ''F'' THEN ''FATAL''' || chr(10) ||
					'			WHEN ''E'' THEN ''ERROR''' || chr(10) ||
					'			WHEN ''W'' THEN ''WARNING''' || chr(10) ||
					'			WHEN ''N'' THEN ''NOTICE''' || chr(10) ||
					'			WHEN ''I'' THEN ''INFO''' || chr(10) ||
					'			WHEN ''B'' THEN ''BUG''' || chr(10) ||
					'			ELSE li.SEVERITY ' || chr(10) ||
					'		END ISSUE_HEADING,' || chr(10) ||
					'		CASE li.SEVERITY' || chr(10) ||
					'			WHEN ''F'' THEN ''class="fatal"''' || chr(10) ||
					'			WHEN ''E'' THEN ''class="error"''' || chr(10) ||
					'			WHEN ''W'' THEN ''class="warning"''' || chr(10) ||
					'			WHEN ''N'' THEN ''class="notice"''' || chr(10) ||
					'			ELSE ''''' || chr(10) ||
					'		END ISSUE_CLASS' || chr(10);
		IF t_excludeAffectedCerts IS NULL THEN
			t_query := t_query ||
					'	FROM lint_cert_issue lci, lint_issue li, ca' || chr(10) ||
					'	WHERE lci.LINT_ISSUE_ID = li.ID' || chr(10) ||
					'		AND lci.ISSUER_CA_ID = ca.ID' || chr(10) ||
					'		AND ca.LINTING_APPLIES' || chr(10);
			IF t_linter IS NOT NULL THEN
				t_query := t_query ||
					'		AND li.LINTER = ''' || t_linter || '''' || chr(10);
			END IF;
			t_query := t_query ||
					'		AND lci.NOT_BEFORE >= $1' || chr(10) ||
					'	GROUP BY li.ID, li.SEVERITY, li.ISSUE_TEXT' || chr(10);
		ELSE
			t_query := t_query ||
					'	FROM lint_issue li' || chr(10);
			IF t_linter IS NOT NULL THEN
				t_query := t_query ||
					'		AND li.LINTER = ''' || t_linter || '''' || chr(10);
			END IF;
		END IF;
		IF t_sort = 1 THEN
			t_query := t_query ||
					'	ORDER BY ISSUE_TYPE, li.ISSUE_TEXT ' || t_orderBy;
		ELSIF t_sort = 2 THEN
			t_query := t_query ||
					'	ORDER BY li.ISSUE_TEXT ' || t_orderBy;
		ELSIF t_sort = 3 THEN
			t_query := t_query ||
					'	ORDER BY NUM_CERTS ' || t_orderBy;
		END IF;

		FOR l_record IN EXECUTE t_query USING t_minNotBefore LOOP
			IF t_outputType = 'json' THEN
				t_output := t_output || row_to_json(l_record, FALSE);
			ELSIF t_outputType = 'html' THEN
				t_output := t_output ||
'    <TR>
      <TD ' || l_record.ISSUE_CLASS || '>' || l_record.ISSUE_HEADING || '</TD>
      <TD ' || l_record.ISSUE_CLASS || '>' || l_record.ISSUE_TEXT || '</TD>
      <TD><A href="?' || t_cmd || '=' || l_record.ID::text || t_minNotBeforeString || '">';
				IF l_record.NUM_CERTS = -1 THEN
					t_output := t_output || '?';
				ELSE
					t_output := t_output || l_record.NUM_CERTS;
				END IF;
				t_output := t_output || '</A></TD>
    </TR>
';
			END IF;
		END LOOP;

		IF t_outputType = 'html' THEN
			t_output := t_output ||
'  </TABLE>
';
		END IF;

	ELSE
		t_output := t_output || ' <SPAN class="whiteongrey">Error</SPAN>
<BR><BR>''' || name || ''' is an unsupported action!
';

	END IF;

	IF t_outputType = 'html' THEN
		t_output :=                                                                                                                                                                                                                          
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::integer || '
Content-Type: text/html; charset=UTF-8
[END_HEADERS]
' || t_output || '
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
	END IF;

	IF t_cacheResponse THEN
		INSERT INTO cached_response (
				PAGE_NAME, GENERATED_AT, RESPONSE_BODY
			)
			VALUES (
				t_type, statement_timestamp(), t_output
			)
			ON CONFLICT (PAGE_NAME) DO UPDATE
				SET GENERATED_AT = statement_timestamp(),
					RESPONSE_BODY = t_output;
		RETURN 'Cached';
	ELSE
		RETURN t_output;
	END IF;

EXCEPTION
	WHEN no_data_found THEN
		RETURN
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::integer || '
Content-Type: text/html; charset=UTF-8
[END_HEADERS]
' || coalesce(t_output, '') || '<BR><BR>' || SQLERRM ||
'</BODY>
</HTML>
';
	WHEN others THEN
		GET STACKED DIAGNOSTICS t_temp = PG_EXCEPTION_CONTEXT;
		RETURN
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::integer || '
Content-Type: text/html; charset=UTF-8
[END_HEADERS]
' || coalesce(t_output, '') || '<BR><BR>' || html_escape(SQLERRM) || '<BR><BR>' || html_escape(coalesce(t_temp, '')) || '<BR><BR>' || html_escape(coalesce(t_query, ''));
END;
$$ LANGUAGE plpgsql;
