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
		'graph', 'Certification Graph', NULL,
		'nodes', 'Graph Nodes', NULL,
		'h', 'PKI Hierarchy', NULL,
		'pv', 'pv-certificate-viewer', NULL,
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
		'zlint', 'ZLint', NULL,
		'keylint', 'keylint', NULL,
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
	t_issuerCertificate	certificate.CERTIFICATE%TYPE;
	t_tbsCertificate	bytea;
	t_certSummary		text;
	t_caID				ca.ID%TYPE;
	t_caName			ca.NAME%TYPE;
	t_serialNumber		bytea;
	t_spkiSHA256		bytea;
	t_nameType			text;
	t_nameType_oid		text;
	t_text				text;
	t_offset			integer;
	t_pos1				integer;
	t_temp0				text;
	t_temp				text;
	t_temp2				text;
	t_temp3				text;
	t_temp4				text;
	t_temp5				text;
	t_select			text;
	t_from				text;
	t_where				text;
	t_nameValue			text;
	t_certID_field		text;
	t_entryTimestamp_field	text;
	t_query				text;
	t_sort				integer;
	t_needMinEntryTimestamp	boolean;
	t_groupBy			text			:= 'none';
	t_groupByParameter	text			:= 'none';
	t_direction			text;
	t_oppositeDirection	text;
	t_dirSymbol			text;
	t_issuerO			text;
	t_issuerOParameter	text;
	t_orderBy			text			:= 'ASC';
	t_opt				text;
	t_maxAge			timestamp without time zone;
	t_cacheResponse		boolean			:= FALSE;
	t_useCachedResponse	boolean			:= FALSE;
	t_linter			linter_type;
	t_linters			text;
	t_showCABLint		boolean;
	t_showX509Lint		boolean;
	t_showZLint			boolean;
	t_showMetadata		boolean;
	t_rsaModulus		bytea;
	t_hasROCAFingerprint	boolean;
	t_hasClosePrimes	boolean;
	t_publicKeyProblems	text;
	t_action			text;
	t_certType			integer;
	t_showMozillaDisclosure	boolean;
	t_ctp				ca_trust_purpose%ROWTYPE;
	t_ctp2				ca_trust_purpose%ROWTYPE;
	t_ctp3				ca_trust_purpose%ROWTYPE;
	t_useReverseIndex	boolean			:= FALSE;
	t_joinToCertificate_table	text;
	t_showIdentity		boolean;
	t_minNotBefore		date;
	t_minNotBeforeString	text;
	t_excludeExpired	text;
	t_excludeAffectedCerts	text;
	t_excludeCAs		integer[];
	t_excludeCAsString	text;
	t_deduplicate		boolean			:= FALSE;
	t_match				text;
	t_tsqueryFunction	text;
	t_searchProvider	text;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_issuerCAID_table	text;
	t_commonName_field	text;
	t_notBefore_field	text;
	t_notAfter_field	text;
	t_serialNumber_field	text;
	t_feedUpdated		timestamp;
	t_caPublicKey		ca.PUBLIC_KEY%TYPE;
	t_numIssued			ca.NUM_ISSUED%TYPE;
	t_numExpired		ca.NUM_EXPIRED%TYPE;
	t_count				bigint;
	t_count2			bigint;
	t_pageNo			bigint;
	t_resultsPerPage	integer			:= 100;
	l_record			RECORD;
	l_record2			RECORD;
	t_purposeOID		text;
	t_purpose			text;
	t_cacheControlMaxAge	integer		:= 300;
	t_versions			text[];
	t_date				date;
	t_onlyOneChain		boolean;
	t_isJSONOutputSupported    boolean	:= FALSE;
	t_showSQL			boolean			:= FALSE;
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
				RETURN download_cert(t_value);
			ELSIF t_type IN ('ID', 'Certificate ASN.1', 'Certification Graph', 'PKI Hierarchy', 'pv-certificate-viewer', 'CA ID') THEN
				BEGIN
					EXIT WHEN t_value::bigint IS NOT NULL;
				EXCEPTION
					WHEN OTHERS THEN
						NULL;
				END;
			ELSIF t_type = 'Graph Nodes' THEN
				RETURN certification_graph(t_value);
			ELSIF t_type = 'CT Entry ID' THEN
				BEGIN
					IF t_value::bigint IS NOT NULL THEN
						t_isJSONOutputSupported := TRUE;
						EXIT;
					END IF;
				EXCEPTION
					WHEN OTHERS THEN
						NULL;
				END;
			ELSIF t_type IN (
						'Simple', 'Advanced', 'CA Name'
					) THEN
				EXIT;
			ELSIF t_type IN (
						'CA/B Forum lint', 'X.509 lint', 'ZLint', 'keylint', 'Lint',
						'Identity', 'Common Name', 'Email Address',
						'Organizational Unit Name', 'Organization Name',
						'Domain Name', 'Email Address (SAN)', 'IP Address'
					) THEN
				t_isJSONOutputSupported := TRUE;
				EXIT;
			ELSIF t_type = 'SHA-1(Certificate)' THEN
				EXIT WHEN length(t_bytea) = 20;
			ELSIF t_type IN (
						'SHA-1(SubjectPublicKeyInfo)', 'SHA-1(Subject)'
					) THEN
				IF length(t_bytea) = 20 THEN
					t_isJSONOutputSupported := TRUE;
					EXIT;
				END IF;
			ELSIF t_type = 'SHA-256(Certificate)' THEN
				EXIT WHEN length(t_bytea) = 32;
			ELSIF t_type = 'SHA-256(SubjectPublicKeyInfo)' THEN
				IF length(t_bytea) = 32 THEN
					t_isJSONOutputSupported := TRUE;
					EXIT;
				END IF;
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
	IF lower(t_outputType) IN ('forum', 'gen-add-chain', 'monitored-logs') THEN
		t_type := lower(t_outputType);
		t_title := t_type;
		t_outputType := 'html';
	ELSIF lower(t_outputType) LIKE '%.json' THEN
		t_type := lower(t_outputType);
		t_outputType := 'json';
		t_isJSONOutputSupported := TRUE;
	ELSIF lower(t_outputType) IN ('revoked-intermediates', 'mozilla-certvalidations', 'mozilla-certvalidations-by-root', 'mozilla-certvalidations-by-owner', 'mozilla-certvalidations-by-version',
									'mozilla-disclosures', 'mozilla-onecrl', 'microsoft-disclosures', 'apple-disclosures', 'ca-issuers', 'ocsp-responders', 'ocsp-response', 'test-websites', 'cert-populations') THEN
		t_type := lower(t_outputType);
		t_title := t_type;
		t_outputType := 'html';
		t_useCachedResponse := TRUE;
	ELSIF lower(t_outputType) IN ('linttbscert', 'lintcert') THEN
		t_type := lower(t_outputType);
		t_outputType := 'html';
	ELSIF lower(t_outputType) IN ('advanced') THEN
		t_type := 'Advanced';
		t_outputType := 'html';
	END IF;

	IF (t_outputType = 'json') AND t_isJSONOutputSupported THEN
		t_output :=
'[BEGIN_HEADERS]
Content-Type: application/json
[END_HEADERS]
';
	ELSIF t_outputType NOT IN ('html', 'atom') THEN
		RAISE no_data_found USING MESSAGE = 'Unsupported output type: ' || html_escape(t_outputType);
	END IF;

	t_temp := upper(get_parameter('match', paramNames, paramValues));
	IF t_temp IS NULL THEN
		IF (position(' -' in coalesce(t_value, '')) > 0)
				OR (position(' +' in coalesce(t_value, '')) > 0)
				OR (position(' OR ' in upper(coalesce(t_value, ''))) > 0)
				OR (position(' AND ' in upper(coalesce(t_value, ''))) > 0) THEN
			t_match := 'Any';
		ELSIF position(' ' in coalesce(t_value, '')) > 0 THEN
			t_match := 'Single';
		ELSIF (t_value LIKE '%:*') AND (t_value NOT LIKE '% %') THEN
			t_match := 'FTS';
		ELSE
			t_match := 'ILIKE';
		END IF;
	ELSIF t_temp = 'ANY' THEN
		t_match := 'Any';
	ELSIF t_temp = 'SINGLE' THEN
		t_match := 'Single';
	ELSIF t_temp = 'ILIKE' THEN
		t_match := 'ILIKE';
	ELSIF t_temp = 'LIKE' THEN
		t_match := 'LIKE';
	ELSIF t_temp = 'FTS' THEN
		t_match := 'FTS';
	ELSE
		t_match := '=';
	END IF;

	IF t_match = 'Any' THEN
		t_tsqueryFunction := 'websearch_to_tsquery';
	ELSIF t_match = 'FTS' THEN
		t_tsqueryFunction := 'to_tsquery';
	ELSE
		t_tsqueryFunction := 'plainto_tsquery';
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
		t_match := '=';
	ELSIF t_type = 'CT Entry ID' THEN
		t_title := 'CT:' || t_value;
		t_match := '=';
	ELSIF t_type = 'CA ID' THEN
		t_title := 'CA:' || t_value;
		t_match := '=';
	ELSIF t_type = 'CA Name' THEN
		t_title := 'CA:' || t_value;
	ELSIF t_type = 'Serial Number' THEN
		t_value := encode(t_bytea, 'hex');
		t_title := 'Serial#' || t_value;
		t_match := '=';
	ELSIF t_type = 'Subject Key Identifier' THEN
		t_value := encode(t_bytea, 'hex');
		t_title := 'SKI#' || t_value;
		t_match := '=';
	ELSIF t_type = 'Identity' THEN
		NULL;
	ELSIF t_type = 'Common Name' THEN
		t_nameType := 'commonName';
		t_nameType_oid := '2.5.4.3';
	ELSIF t_type = 'Email Address' THEN
		t_nameType := 'emailAddress';
		t_nameType_oid := '1.2.840.113549.1.9.1';
	ELSIF t_type = 'Organizational Unit Name' THEN
		t_nameType := 'organizationalUnitName';
		t_nameType_oid := '2.5.4.11';
	ELSIF t_type = 'Organization Name' THEN
		t_nameType := 'organizationName';
		t_nameType_oid := '2.5.4.10';
	ELSIF t_type = 'Domain Name' THEN
		t_nameType := 'dNSName';
		t_nameType_oid := 'san:dNSName';
	ELSIF t_type = 'Email Address (SAN)' THEN
		t_nameType := 'rfc822Name';
		t_nameType_oid := 'san:rfc822Name';
	ELSIF t_type = 'IP Address' THEN
		t_nameType := 'iPAddress';
		t_nameType_oid := 'san:iPAddress';
	ELSIF lower(t_type) LIKE '%lint' THEN
		IF t_type = 'Lint' THEN
			t_linters := 'cablint,x509lint,zlint,keylint';
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
		t_match := '=';
	END IF;

	IF t_title IS NULL THEN
		t_title := coalesce(t_value, '');
	END IF;

	t_temp := get_parameter('minNotBefore', paramNames, paramValues);
	IF t_temp IS NULL THEN
		t_minNotBefore := (now() AT TIME ZONE 'UTC' - interval '1 week')::date;
		t_minNotBeforeString := '';
	ELSE
		t_minNotBefore := t_temp::date;
		t_minNotBeforeString := '&minNotBefore=' || t_temp;
	END IF;

	t_temp := get_parameter('exclude', paramNames, paramValues);
	IF lower(coalesce(',' || t_temp || ',', 'nothing')) LIKE ',expired,' THEN
		t_excludeExpired := '&exclude=expired';
	END IF;

	IF upper(coalesce(get_parameter('deduplicate', paramNames, paramValues), 'N')) = 'Y' THEN
		t_deduplicate := TRUE;
	END IF;

	t_temp := get_parameter('search', paramNames, paramValues);
	IF lower(coalesce(t_temp, 'crt.sh')) = 'censys' THEN
		t_searchProvider := '&search=censys';
	END IF;

	t_opt := coalesce(get_parameter('opt', paramNames, paramValues), '');
	IF t_opt != '' THEN
		t_opt := html_escape(t_opt) || ',';
	END IF;

	IF upper(coalesce(get_parameter('showSQL', paramNames, paramValues), 'N')) = 'Y' THEN
		t_showSQL := TRUE;
	END IF;

	IF t_outputType IN ('html', 'json') THEN
		IF lower(t_type) LIKE '%lint%' THEN
			t_groupBy := coalesce(get_parameter('group', paramNames, paramValues), '');
			t_direction := coalesce(get_parameter('dir', paramNames, paramValues), 'v');
		ELSE
			t_groupBy := coalesce(get_parameter('group', paramNames, paramValues), 'none');
			t_direction := coalesce(get_parameter('dir', paramNames, paramValues), '^');
		END IF;

		t_groupByParameter := t_groupBy;
		IF t_groupByParameter != '' THEN
			t_groupByParameter := '&group=' || html_escape(t_groupByParameter);
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
		t_count := coalesce(get_parameter('maxage', paramNames, paramValues), '172800')::integer;
		t_cacheResponse := (t_count = 0);
		t_maxAge := now() AT TIME ZONE 'UTC' - (interval '1 second' * t_count);
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
	t_output := coalesce(t_output, '');
	IF t_outputType = 'html' THEN
		t_output :=
'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
  <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
  <TITLE>crt.sh | ' || html_escape(t_title) || '</TITLE>
  <META name="description" content="Free CT Log Certificate Search Tool from Sectigo (formerly Comodo CA)">
  <META name="keywords" content="crt.sh, CT, Certificate Transparency, Certificate Search, SSL Certificate, Sectigo, Comodo CA">
  <LINK href="//fonts.googleapis.com/css?family=Roboto+Mono|Roboto:400,400i,700,700i" rel="stylesheet">
';
		IF (t_type = 'Certificate ASN.1')
				OR ((t_type = 'ocsp-response') AND (coalesce(get_parameter('type', paramNames, paramValues), 'dump') = 'asn1')) THEN
			t_output := t_output ||
'  <LINK rel="stylesheet" href="/asn1js/index.css" type="text/css">
';
		ELSIF t_type = 'Certification Graph' THEN
			t_output := t_output ||
'  <SCRIPT src="//cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.min.js"></SCRIPT>
  <SCRIPT src="//cdn.jsdelivr.net/npm/cytoscape@3.15.1/dist/cytoscape.min.js"></SCRIPT>
  <SCRIPT src="//cdn.jsdelivr.net/npm/dagre@0.8.5/dist/dagre.min.js"></SCRIPT>
  <SCRIPT src="//cdn.jsdelivr.net/npm/cytoscape-dagre@2.2.2/cytoscape-dagre.min.js"></SCRIPT>
  <STYLE type="text/css">
    #cy {
      width: 100%;
      height: 600px;
      position: relative;
    }
  </STYLE>
';
		ELSIF t_type = 'pv-certificate-viewer' THEN
			t_output := t_output ||
'  <SCRIPT type="module" src="//unpkg.com/@peculiar/certificates-viewer@latest/dist/peculiar/peculiar.esm.js"></SCRIPT>
  <SCRIPT nomodule src="//unpkg.com/@peculiar/certificates-viewer@latest/dist/peculiar/peculiar.js"></SCRIPT>
  <LINK rel="stylesheet" href="//unpkg.com/@peculiar/certificates-viewer@latest/dist/peculiar/peculiar.css">
';
		ELSIF t_type = 'mozilla-certvalidations' THEN
			t_output := t_output ||
'  <SCRIPT src="//cdnjs.cloudflare.com/ajax/libs/dygraph/2.0.0/dygraph.min.js"></SCRIPT>
  <LINK rel="stylesheet" src="//cdnjs.cloudflare.com/ajax/libs/dygraph/2.0.0/dygraph.min.css" />
  <STYLE type="text/css">
    #graph { width: 800px; height: 400px; }
    #graph, #graph_toggles, #graph_labels { float: left; margin: 0 1em 1em 0; }
    #graph_toggles label { display: block; font-weight: bold; }
    .many .dygraph-legend > span { display: none; }
    .many .dygraph-legend > span.highlight { display: inline }
  </STYLE>
';
		ELSIF t_type = 'monitored-logs' THEN
			t_cacheControlMaxAge := -1;
			t_output := t_output ||
'  <STYLE type="text/css">
    table tr:nth-child(2n+5) {
      background: #E7E7E7
    }
  </STYLE>
';
		END IF;
		t_output := t_output ||
'  <STYLE type="text/css">
';
		IF t_type NOT IN ('mozilla-disclosures', 'microsoft-disclosures', 'apple-disclosures', 'ca-issuers', 'ocsp-responders', 'test-websites') THEN
			t_output := t_output ||
'    a {
      white-space: nowrap;
    }
';
		ELSIF t_type = 'ca-issuers' THEN
			t_output := t_output ||
'    a {
      word-wrap: break-word;
    }
';
		END IF;
		t_output := t_output ||
'    body {
      color: #888888;
      font: 12pt Roboto, sans-serif;
      padding-top: 10px;
      text-align: center
    }
    form {
      margin: 0px
    }
    span {
      border-radius: 10px
    }
    span.heading {
      color: #888888;
      font: 12pt Roboto, sans-serif
    }
    span.title {
      background-color: #00B373;
      color: #FFFFFF;
      font: bold 18pt Roboto, sans-serif;
      padding: 0px 5px
    }
    span.text {
      color: #888888;
      font: 10pt Roboto, sans-serif
    }
    span.whiteongrey {
      background-color: #D9D9D6;
      color: #FFFFFF;
      font: bold 18pt Roboto, sans-serif;
      padding: 0px 5px
    }
    table {
      border-collapse: collapse;
      color: #222222;
      font: 10pt Roboto, sans-serif;
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
      font: bold italic 12pt Roboto, sans-serif;
      padding: 20px 0px 0px;
      text-align: center
    }
    th.options, td.options {
      border: none;
      vertical-align: middle
    }
    td.text {
      font: 10pt "Roboto Mono", sans-serif;
      padding: 2px 20px
    }
    td.heading {
      border: none;
      color: #888888;
      font: 12pt Roboto, sans-serif;
      padding-top: 20px;
      text-align: center
    }
    table.lint td, th {
      text-align: center
    }
    .button {
      background-color: #00B373;
      border-radius: 10px;
      color: #FFFFFF;
      font: bold 13pt Roboto, sans-serif
    }
    .copyright {
      font: 8pt Roboto, sans-serif;
      color: #00B373
    }
    .input {
      border: 1px solid #888888;
      font-weight: bold;
      text-align: center
    }
    .small {
      font: 8pt Roboto, sans-serif;
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
    *:focus {
      outline: 0px transparent !important
    }
  </STYLE>
</HEAD>
<BODY>
  <A style="text-decoration:none" href="/"><SPAN class="title">crt.sh</SPAN></A>&nbsp;';
	END IF;

	IF t_type = 'Invalid value' THEN
		RAISE no_data_found USING MESSAGE = t_type || ': ''' || html_escape(t_value) || '''';

	ELSIF t_type = 'Simple' THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
  <BR><BR><BR><BR>
  Enter an <B>Identity</B> (Domain Name, Organization Name, etc),
  <BR>a <B>Certificate Fingerprint</B> (SHA-1 or SHA-256) or a <B>crt.sh ID</B>:
  <BR><BR>
  <FORM name="search_form" method="GET" onsubmit="return (this.q.value != '''')">
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
        t_url = "//search.censys.io/certificates-legacy?q=";
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
            t_url += "parsed.names:" + encodeURIComponent("\"" + value + "\"");
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
        with (document.search_form) {
          if (match.options[match.selectedIndex].value != "")
            t_url += "&match=" + match.options[match.selectedIndex].value;
        }
        if (document.search_form.deduplicate.checked)
          t_url += "&deduplicate=Y";
        if (document.search_form.showSQL.checked)
          t_url += "&showSQL=Y";
      }
      window.location = t_url;
    }
  </SCRIPT>
  <FORM name="search_form" method="GET" onsubmit="return false">
    Enter search term:
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
          <BR><DIV style="border:1px solid #AAAAAA;margin-bottom:5px;padding:4px 2px;text-align:left">
            &nbsp;<SELECT name="match">
              <OPTION value="" selected>Autoselect</OPTION>
              <OPTION value="=">=</OPTION>
              <OPTION value="ILIKE">ILIKE</OPTION>
              <OPTION value="LIKE">LIKE</OPTION>
              <OPTION value="single">Single</OPTION>
              <OPTION value="any">Any</OPTION>
              <OPTION value="FTS">Full Text Search</OPTION>
            </SELECT> Identity matching
            <BR><INPUT type="checkbox" name="excludeExpired"';
		IF t_excludeExpired IS NOT NULL THEN
			t_output := t_output || ' checked';
		END IF;
		t_output := t_output || '> Exclude expired certificates?
            <BR><INPUT type="checkbox" name="deduplicate"';
		IF t_deduplicate THEN
			t_output := t_output || ' checked';
		END IF;
		t_output := t_output || '> Deduplicate (pre)certificate pairs?
            <BR><INPUT type="checkbox" name="showSQL"';
		IF t_showSQL THEN
			t_output := t_output || ' checked';
		END IF;
		t_output := t_output || '> Show SQL?
            <HR>
            &nbsp;Or, <INPUT type="checkbox" name="searchCensys"';
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
          <BR><BR><BR><HR><BR>
          <SPAN class="heading">Select linting options:</SPAN>
          <BR><SELECT name="linter" size="3">
            <OPTION value="cablint">cablint</OPTION>
            <OPTION value="x509lint">x509lint</OPTION>
            <OPTION value="zlint" selected>zlint</OPTION>
            <OPTION value="keylint">keylint</OPTION>
            <OPTION value="lint">ALL</OPTION>
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
      <TR>
        <TD colspan="3" style="border:none">
          <BR><BR><HR>
        </TD>
      </TR>
      <TR>
        <TD style="border:none">
          <TABLE>
            <TR>
              <TD>crt.sh</TD>
              <TD>
                <A href="//groups.google.com/g/crtsh">Forum</A>
                <BR><A href="/cert-populations">Certificate Populations</A>
                <BR><A href="/revoked-intermediates">Revoked Intermediates</A>
                <BR><A href="/ca-issuers">CA Issuers</A>
                <BR><A href="/ocsp-responders">OCSP Responders</A>
                <BR><A href="/test-websites">Test Websites</A>
              </TD>
            </TR>
            <TR>
              <TD>Linting</TD>
              <TD>
                <A href="/linttbscert">TBSCertificate Linter</A>
                <BR><A href="/lintcert">Certificate Linter</A>
              </TD>
            </TR>
          </TABLE>
        </TD>
        <TD style="border:none">&nbsp;</TD>
        <TD style="border:none">
          <TABLE>
            <TR>
              <TD>CT</TD>
              <TD>
                <A href="/monitored-logs">Monitored Logs</A>
                <BR><A href="/gen-add-chain">Certificate Submission Assistant</A>
              </TD>
            </TR>
            <TR>
              <TD>Mozilla</TD>
              <TD>
                <A href="/mozilla-disclosures">CA Certificate Disclosures</A>
                <BR><A href="/mozilla-certvalidations">Certificate Validations</A>
                <BR><A href="/mozilla-onecrl">OneCRL</A>
              </TD>
            </TR>
            <TR>
              <TD>Apple</TD>
              <TD>
                <A href="/apple-disclosures">CA Certificate Disclosures</A>
              </TD>
            </TR>
          </TABLE>
        </TD>
      <TR>
    </TABLE>
  </FORM>
  <SCRIPT type="text/javascript">
    document.search_form.q.focus();
  </SCRIPT>';

	ELSIF t_type = 'cert-populations' THEN
		t_cacheControlMaxAge := -1;
		t_output := t_output ||
'  <SPAN class="whiteongrey">Certificate Populations</SPAN>
  <BR><BR>
  <TABLE>
    <TR>
      <TH rowspan="2">CA Owner</TH>
      <TH colspan="2">Certificates</TH>
      <TH colspan="2">Precertificates</TH>
    </TR>
    <TR>
      <TH>ALL</TH>
      <TH>Unexpired</TH>
      <TH>ALL</TH>
      <TH>Unexpired</TH>
    </TR>
';
		FOR l_record IN (
			SELECT sub.OWNER,
					sum(coalesce(sub.NUM_ISSUED[1], 0)) CERT_POPULATION,
					(sum(coalesce(sub.NUM_ISSUED[1], 0)) - sum(coalesce(sub.NUM_EXPIRED[1], 0))) CERT_POPULATION_UNEXPIRED,
					sum(coalesce(sub.NUM_ISSUED[2], 0)) PRECERT_POPULATION,
					(sum(coalesce(sub.NUM_ISSUED[2], 0)) - sum(coalesce(sub.NUM_EXPIRED[2], 0))) PRECERT_POPULATION_UNEXPIRED
				FROM (
						SELECT max(coalesce(coalesce(nullif(trim(cc.SUBORDINATE_CA_OWNER), ''), nullif(trim(cc.CA_OWNER), '')), cc.INCLUDED_CERTIFICATE_OWNER)) as OWNER,
								ca.NUM_ISSUED, ca.NUM_EXPIRED
							FROM ccadb_certificate cc, ca_certificate cac, ca
							WHERE cc.CERTIFICATE_ID = cac.CERTIFICATE_ID
								AND cac.CA_ID = ca.ID
							GROUP BY ca.ID
					) sub
				GROUP BY sub.OWNER
				ORDER BY CERT_POPULATION DESC
		) LOOP
			t_output := t_output ||
'    <TR>
      <TD>' || coalesce(l_record.OWNER, '?') || '</TD>
      <TD style="text-align:right">' || to_char(l_record.CERT_POPULATION, '999G999G999G999G999') || '</TD>
      <TD style="text-align:right">' || to_char(l_record.CERT_POPULATION_UNEXPIRED, '999G999G999G999G999') || '</TD>
      <TD style="text-align:right">' || to_char(l_record.PRECERT_POPULATION, '999G999G999G999G999') || '</TD>
      <TD style="text-align:right">' || to_char(l_record.PRECERT_POPULATION_UNEXPIRED, '999G999G999G999G999') || '</TD>
    </TR>
';
		END LOOP;
		t_output := t_output ||
'</TABLE>
';

	ELSIF t_type = 'forum' THEN
		RETURN
'<HTML><HEAD><META http-equiv="refresh" content="0;url=https://groups.google.com/g/crtsh"/></HEAD></HTML>';

	ELSIF t_type = 'logs.json' THEN
		t_temp := coalesce(get_parameter('include', paramNames, paramValues), 'active');
		t_output := t_output || '{' || chr(10) || '  "logs": [' || chr(10);
		FOR l_record IN (
					SELECT ctl.NAME, ctl.PUBLIC_KEY, ctl.URL, ctl.MMD_IN_SECONDS
						FROM ct_log ctl
						WHERE ctl.IS_ACTIVE = CASE WHEN t_temp = 'all' THEN ctl.IS_ACTIVE ELSE 't' END
						ORDER BY ctl.NAME
				) LOOP
			t_output := t_output
								|| '    {' || chr(10)
								|| '      "description": "' || l_record.NAME || '",' || chr(10);
			IF l_record.PUBLIC_KEY IS NOT NULL THEN
				t_output := t_output
								|| '      "log_id": "' || encode(digest(l_record.PUBLIC_KEY, 'sha256'), 'base64') || '",' || chr(10)
								|| '      "key": "' || replace(encode(l_record.PUBLIC_KEY, 'base64'), chr(10), '') || '",' || chr(10);
			END IF;
			t_output := t_output
								|| '      "url": "' || l_record.URL || '",' || chr(10)
								|| '      "maximum_merge_delay": ' || coalesce(l_record.MMD_IN_SECONDS::text, '') || chr(10)
								|| '    },' || chr(10);
		END LOOP;
		t_output := rtrim(t_output, ',' || chr(10)) || chr(10) || '  ]' || chr(10) || '}';

	ELSIF t_type = 'monitored-logs' THEN
		t_temp := lower(coalesce(get_parameter('recognizedBy', paramNames, paramValues), ''));
		t_output := t_output ||
'  <SPAN class="whiteongrey">Monitored Logs</SPAN>
  <BR>
  <TABLE>
    <TR><TD colspan="11" class="heading">CT Logs currently monitored';
		IF t_temp = 'chromium' THEN
			t_output := t_output || ' (that are Usable with Chromium-based browsers)';
		END IF;
		t_output := t_output || ':</TD></TR>
    <TR>
      <TH rowspan="2">Operator</TH>
      <TH rowspan="2">URL</TH>
      <TH rowspan="2">MMD<BR><SPAN class="small">(hrs)</SPAN></TH>
      <TH rowspan="2">Latest STH<BR><SPAN class="small">(UTC)</SPAN></TH>
      <TH colspan="3">Entries</TH>
      <TH rowspan="2">Last Contacted<BR><SPAN class="small">(UTC)</SPAN></TH>
      <TH>Google</TH>
      <TH><A href="monitored-logs?recognizedBy=Chromium">Chromium</A></TH>
      <TH>Apple</TH>
    </TR>
    <TR>
      <TH>Tree Size</TH>
      <TH>Backlog</TH>
      <TH>Latest Entry Age</TH>
      <TH>Uptime %</TH>
      <TH>Status (added)</TH>
      <TH>Status (since)</TH>
    </TR>';
		FOR l_record IN (
					SELECT ctl.ID,
							coalesce(ctlo.DISPLAY_STRING, ctl.OPERATOR) AS OPERATOR,
							ctl.URL, ctl.TREE_SIZE,
							(coalesce(ctl.TREE_SIZE, 0) - latest.ENTRY_ID - 1) AS BACKLOG,
							((now() AT TIME ZONE 'UTC') - coalesce(latest2.ENTRY_TIMESTAMP, now() AT TIME ZONE 'UTC')) AS BACKLOG_TIME,
							ctl.LATEST_UPDATE, ctl.LATEST_STH_TIMESTAMP, ctl.MMD_IN_SECONDS,
							CASE WHEN coalesce(ctl.LATEST_STH_TIMESTAMP + (ctl.MMD_IN_SECONDS || ' seconds')::interval, now() AT TIME ZONE 'UTC') <= now() AT TIME ZONE 'UTC'
								THEN ' style="color:#FF0000"'
								ELSE ''
							END FONT_STYLE,
							ctl.CHROME_VERSION_ADDED, ctl.CHROME_ISSUE_NUMBER, ctl.CHROME_INCLUSION_STATUS,
							ctl.CHROME_FINAL_TREE_SIZE, ctl.CHROME_DISQUALIFIED_AT, ctl.GOOGLE_UPTIME,
							CASE WHEN coalesce(ctl.GOOGLE_UPTIME::numeric, 100) < 99
								THEN ';color:#FF0000'
								ELSE ''
							END UPTIME_FONT_STYLE,
							ctl.APPLE_INCLUSION_STATUS, ctl.APPLE_LAST_STATUS_CHANGE
						FROM ct_log ctl
								LEFT OUTER JOIN ct_log_operator ctlo ON (ctl.OPERATOR = ctlo.OPERATOR)
								LEFT JOIN LATERAL (
									SELECT coalesce(max(ENTRY_ID), -1) ENTRY_ID
										FROM ct_log_entry ctle
										WHERE ctle.CT_LOG_ID = ctl.ID
								) latest ON TRUE
								LEFT JOIN LATERAL (
									SELECT ctle2.ENTRY_TIMESTAMP
										FROM ct_log_entry ctle2
										WHERE ctle2.CT_LOG_ID = ctl.ID
											AND ctle2.ENTRY_ID = latest.ENTRY_ID
								) latest2 ON TRUE
						WHERE ctl.IS_ACTIVE
						ORDER BY ctl.TREE_SIZE DESC NULLS LAST
				) LOOP
			IF (t_temp = 'chromium') AND (coalesce(l_record.CHROME_INCLUSION_STATUS, '') != 'Usable') THEN
				CONTINUE;
			END IF;

			t_output := t_output || '
    <TR>
      <TD' || l_record.FONT_STYLE || '>' || l_record.OPERATOR || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.URL || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce((l_record.MMD_IN_SECONDS / 60 / 60)::text, '?') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce(to_char(l_record.LATEST_STH_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'), '') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce(l_record.TREE_SIZE::text, '') || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || l_record.BACKLOG::text || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || date_trunc('second', l_record.BACKLOG_TIME)::text || '</TD>
      <TD' || l_record.FONT_STYLE || '>' || coalesce(to_char(l_record.LATEST_UPDATE, 'YYYY-MM-DD HH24:MI:SS'), '') || '</TD>
      <TD style="text-align:right' || l_record.UPTIME_FONT_STYLE || '">' || coalesce(l_record.GOOGLE_UPTIME, '') || '</TD>
      <TD>';
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '<A href="https://code.google.com/p/chromium/issues/detail?id='
									|| l_record.CHROME_ISSUE_NUMBER::text || '" target="_blank">';
			END IF;
			t_output := t_output || coalesce(l_record.CHROME_INCLUSION_STATUS, 'Pending');
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '</A>';
			END IF;
			IF l_record.CHROME_FINAL_TREE_SIZE IS NOT NULL THEN
				t_output := t_output || ' <SPAN class="small">(' || l_record.CHROME_FINAL_TREE_SIZE::text || ')</SPAN>';
			ELSIF l_record.CHROME_DISQUALIFIED_AT IS NOT NULL THEN
				t_output := t_output || ' <SPAN class="small">(' || to_char(l_record.CHROME_DISQUALIFIED_AT, 'YYYY-MM-DD HH24:MI:SS') || ')</SPAN>';
			ELSIF l_record.CHROME_VERSION_ADDED IS NOT NULL THEN
				t_output := t_output || ' (M' || l_record.CHROME_VERSION_ADDED::text || ')';
			END IF;
			t_output := t_output ||
'      </TD>
      <TD>' || coalesce(l_record.APPLE_INCLUSION_STATUS, '');
			IF l_record.APPLE_LAST_STATUS_CHANGE IS NOT NULL THEN
				t_output := t_output || ' <SPAN class="small">(' || to_char(l_record.APPLE_LAST_STATUS_CHANGE, 'YYYY-MM-DD HH24:MI:SS') || ')</SPAN>';
			END IF;
			t_output := t_output || '</TD>
    </TR>';
		END LOOP;

		SELECT sum((coalesce(ctl.TREE_SIZE, 0) - latest.ENTRY_ID - 1)) AS TOTAL_BACKLOG
			INTO t_count
			FROM ct_log ctl
					LEFT OUTER JOIN ct_log_operator ctlo ON (ctl.OPERATOR = ctlo.OPERATOR)
					LEFT JOIN LATERAL (
						SELECT coalesce(max(ENTRY_ID), -1) ENTRY_ID
							FROM ct_log_entry ctle
							WHERE ctle.CT_LOG_ID = ctl.ID
						) latest ON TRUE
				WHERE ctl.IS_ACTIVE;

		t_output := t_output || '
    <TR>
      <TD colspan="4" style="border:0px"></TD>
      <TD>TOTAL</TD>
      <TD>' || t_count::text || ' </TD>
      <TD colspan="5" style="border:0px"></TD>
    </TR>
  </TABLE>
  <TABLE>
    <TR><TD colspan="9" class="heading">CT Logs no longer monitored';
		IF t_temp = 'chromium' THEN
			t_output := t_output || ' (that are no longer Usable with Chromium-based browsers)';
		END IF;
		t_output := t_output || ':</TD></TR>
    <TR>
      <TH rowspan="2">Operator</TH>
      <TH rowspan="2">URL</TH>
      <TH rowspan="2">MMD<BR><SPAN class="small">(hrs)</SPAN></TH>
      <TH rowspan="2">Latest STH<BR><SPAN class="small">(UTC)</SPAN></TH>
      <TH colspan="2">Entries</TH>
      <TH rowspan="2">Last Contacted<BR><SPAN class="small">(UTC)</SPAN></TH>
      <TH rowspan="2"><A href="monitored-logs?recognizedBy=Chromium">Chromium</A> Status (Final<BR>Tree Size or Disqualified At)</TH>
      <TH>Apple</TH>
    </TR>
    <TR>
      <TH>Tree Size</TH>
      <TH>Backlog</TH>
      <TH>Status (since)</TH>
    </TR>';
		FOR l_record IN (
					SELECT ctl.ID,
							coalesce(ctlo.DISPLAY_STRING, ctl.OPERATOR) AS OPERATOR,
							ctl.URL, ctl.TREE_SIZE,
							(coalesce(ctl.TREE_SIZE, 0) - latest.ENTRY_ID - 1) AS BACKLOG,
							ctl.LATEST_UPDATE, ctl.LATEST_STH_TIMESTAMP, ctl.MMD_IN_SECONDS,
							ctl.CHROME_VERSION_ADDED, ctl.CHROME_ISSUE_NUMBER, ctl.CHROME_INCLUSION_STATUS,
							ctl.CHROME_FINAL_TREE_SIZE, ctl.CHROME_DISQUALIFIED_AT,
							ctl.APPLE_INCLUSION_STATUS, ctl.APPLE_LAST_STATUS_CHANGE
						FROM ct_log ctl
								LEFT OUTER JOIN ct_log_operator ctlo ON (ctl.OPERATOR = ctlo.OPERATOR)
								LEFT JOIN LATERAL (
									SELECT coalesce(max(ENTRY_ID), -1) ENTRY_ID
										FROM ct_log_entry ctle
										WHERE ctle.CT_LOG_ID = ctl.ID
								) latest ON TRUE
						WHERE NOT ctl.IS_ACTIVE
							AND ctl.LATEST_STH_TIMESTAMP IS NOT NULL
						ORDER BY ctl.TREE_SIZE DESC NULLS LAST
				) LOOP
			IF (t_temp = 'chromium') AND (coalesce(l_record.CHROME_INCLUSION_STATUS, '') NOT IN ('Readonly', 'Retired')) THEN
				CONTINUE;
			END IF;

			t_output := t_output || '
    <TR>
      <TD>' || l_record.OPERATOR || '</TD>
      <TD>' || l_record.URL || '</TD>
      <TD>' || coalesce((l_record.MMD_IN_SECONDS / 60 / 60)::text, '?') || '</TD>
      <TD>' || coalesce(to_char(l_record.LATEST_STH_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'), '') || '</TD>
      <TD>' || coalesce(l_record.TREE_SIZE::text, '') || '</TD>
      <TD>' || l_record.BACKLOG::text || '</TD>
      <TD>' || coalesce(to_char(l_record.LATEST_UPDATE, 'YYYY-MM-DD HH24:MI:SS'), '') || '</TD>
      <TD>
';
			IF l_record.CHROME_ISSUE_NUMBER IS NOT NULL THEN
				t_output := t_output || '<A href="https://code.google.com/p/chromium/issues/detail?id='
									|| l_record.CHROME_ISSUE_NUMBER::text || '" target="_blank">';
				IF l_record.CHROME_VERSION_ADDED IS NOT NULL THEN
					t_output := t_output || coalesce(l_record.CHROME_INCLUSION_STATUS, 'M' || l_record.CHROME_VERSION_ADDED::text) || '</A>';
					IF l_record.CHROME_FINAL_TREE_SIZE IS NOT NULL THEN
						t_output := t_output || ' <SPAN class="small">(' || l_record.CHROME_FINAL_TREE_SIZE::text || ')</SPAN>';
					ELSIF l_record.CHROME_DISQUALIFIED_AT IS NOT NULL THEN
						t_output := t_output || ' <SPAN class="small">(' || to_char(l_record.CHROME_DISQUALIFIED_AT, 'YYYY-MM-DD HH24:MI:SS') || ')</SPAN>';
					END IF;
					t_output := t_output || chr(10);
				ELSE
					t_output := t_output || coalesce(l_record.CHROME_INCLUSION_STATUS, 'Pending') || '</A>' || chr(10);
				END IF;
			ELSIF l_record.CHROME_INCLUSION_STATUS IS NOT NULL THEN
				t_output := t_output || l_record.CHROME_INCLUSION_STATUS;
			END IF;
			t_output := t_output ||
'      </TD>
      <TD>' || coalesce(l_record.APPLE_INCLUSION_STATUS, '');
			IF l_record.APPLE_LAST_STATUS_CHANGE IS NOT NULL THEN
				t_output := t_output || ' <SPAN class="small">(' || to_char(l_record.APPLE_LAST_STATUS_CHANGE, 'YYYY-MM-DD HH24:MI:SS') || ')</SPAN>';
			END IF;
			t_output := t_output || '</TD>
    </TR>';
		END LOOP;
		t_output := t_output || '
</TABLE>';

	ELSIF t_type = 'gen-add-chain' THEN
		t_temp := get_parameter('b64cert', paramNames, paramValues);
		t_onlyOneChain := lower(coalesce(get_parameter('onlyonechain', paramNames, paramValues), 'n')) = 'y';
		IF t_temp IS NULL THEN
			t_output := t_output ||
'  <SPAN class="whiteongrey">Certificate Submission Assistant</SPAN>
<BR><BR>1. Enter a base64 encoded certificate.
<BR><BR>2. Press the button to generate JSON that you can then submit to a log''s /ct/v1/add-chain API.
<BR>(crt.sh will discover the trust chain for you).
<BR><BR><FORM method="post" name="form1">
  <TEXTAREA name="b64cert" rows=25 cols=65></TEXTAREA>
  <BR><BR><INPUT type="submit" class="button" value="Generate JSON">
</FORM>
<BR><BR><SPAN class="small">Please note: This tool currently finds chains that are trusted by the Mozilla and/or Microsoft and/or Apple root programs.
<BR>FIXME: Look at each log''s /ct/v1/get-roots instead</SPAN>';
		ELSE
			t_certificate := decode(
				replace(replace(t_temp, '-----BEGIN CERTIFICATE-----', ''), '-----END CERTIFICATE-----', ''),
				'base64'
			);

			SELECT c.ID
				INTO t_certificateID
				FROM certificate c
				WHERE digest(c.CERTIFICATE, 'sha256') = digest(t_certificate, 'sha256');

			RETURN
'[BEGIN_HEADERS]
Content-Disposition: attachment; filename="' || upper(encode(digest(t_certificate, 'sha256'), 'hex')) || '_' || coalesce(t_certificateID::text, 'UNKNOWN') || '.add-chain.json"
Content-Type: application/json
[END_HEADERS]
' || generate_add_chain_body(t_certificate, t_onlyOneChain);
		END IF;

	ELSIF t_type = 'linttbscert' THEN
		t_temp := get_parameter('b64tbscert', paramNames, paramValues);
		IF t_temp IS NULL THEN
			t_output := t_output ||
'  <SCRIPT>
    function handleFiles() {
      var reader = new FileReader();
      reader.onload = function(e) {
        document.form1.b64tbscert.value = reader.result;
      }
      reader.readAsText(document.getElementById("fil").files[0]);
    }
  </SCRIPT>
  <SPAN class="whiteongrey">TBSCertificate Linter</SPAN>
  <BR><BR>Pick a file or Paste a base64 encoded TBSCertificate, then press "Lint":
  <BR><BR><INPUT type="file" id="fil" onchange="handleFiles(this.files)" />
  <BR><BR><FORM method="post" name="form1">
    <TEXTAREA name="b64tbscert" rows=25 cols=65></TEXTAREA>
    <BR><BR><INPUT type="submit" class="button" value="Lint">
  </FORM>';
		ELSE
			t_tbsCertificate := decode(
				replace(replace(t_temp, '-----BEGIN CERTIFICATE-----', ''), '-----END CERTIFICATE-----', ''),
				'base64'
			);

			RETURN
'[BEGIN_HEADERS]
Content-Type: text/plain; charset=UTF-8
[END_HEADERS]
' || lint_tbscertificate(t_tbsCertificate);
		END IF;

	ELSIF t_type = 'lintcert' THEN
		t_temp := get_parameter('b64cert', paramNames, paramValues);
		IF t_temp IS NULL THEN
			t_output := t_output ||
'  <SCRIPT>
    function handleFiles() {
      var reader = new FileReader();
      reader.onload = function(e) {
        document.form1.b64cert.value = reader.result;
      }
      reader.readAsText(document.getElementById("fil").files[0]);
    }
  </SCRIPT>
  <SPAN class="whiteongrey">Certificate Linter</SPAN>
  <BR><BR>Pick a file or Paste a base64 encoded Certificate, then press "Lint":
  <BR><BR><INPUT type="file" id="fil" onchange="handleFiles(this.files)" />
  <BR><BR><FORM method="post" name="form1">
    <TEXTAREA name="b64cert" rows=25 cols=65></TEXTAREA>
    <BR><BR><INPUT type="submit" class="button" value="Lint">
  </FORM>';
		ELSE
			t_certificate := decode(
				replace(replace(t_temp, '-----BEGIN CERTIFICATE-----', ''), '-----END CERTIFICATE-----', ''),
				'base64'
			);

			RETURN
'[BEGIN_HEADERS]
Content-Type: text/plain; charset=UTF-8
[END_HEADERS]
' || lint_certificate(t_certificate, FALSE);
		END IF;

	ELSIF t_type = 'revoked-intermediates' THEN
		t_output := t_output || revoked_intermediates();

	ELSIF t_type = 'mozilla-certvalidations-by-root' THEN
		t_outputType := 'csv';
		t_output := 'Date';
		FOR l_record IN (
					SELECT mrh.CERTIFICATE_ID, get_ca_name_attribute(cac.CA_ID) FRIENDLY_NAME, get_ca_name_attribute(cac.CA_ID, 'organizationalUnitName') OU, replace(mrh.CA_OWNER, chr(10), ', ') CA_OWNER
						FROM mozilla_root_hashes mrh
							LEFT OUTER JOIN ca_certificate cac ON (mrh.CERTIFICATE_ID = cac.CERTIFICATE_ID)
							LEFT OUTER JOIN ccadb_certificate cc ON (mrh.CERTIFICATE_ID = cc.CERTIFICATE_ID)
						WHERE mrh.DISPLAY_ORDER IS NOT NULL
						GROUP BY mrh.DISPLAY_ORDER, mrh.CERTIFICATE_ID, cac.CA_ID, mrh.CA_OWNER
						ORDER BY mrh.DISPLAY_ORDER
				) LOOP
			IF l_record.FRIENDLY_NAME IN ('GlobalSign') THEN
				l_record.FRIENDLY_NAME := l_record.OU;
			END IF;
			t_output := t_output || '|[' || coalesce(l_record.CA_OWNER, 'UNKNOWN') || '] ' || replace(l_record.FRIENDLY_NAME, '|', '\|');
		END LOOP;

		FOR l_record IN (
					SELECT mrh.DISPLAY_ORDER, mcvs.SUBMISSION_DATE, mcvs.COUNT
						FROM mozilla_cert_validation_success mcvs, mozilla_root_hashes mrh
						WHERE mcvs.BIN_NUMBER = mrh.BIN_NUMBER
							AND mrh.DISPLAY_ORDER IS NOT NULL
						ORDER BY mcvs.SUBMISSION_DATE, mrh.DISPLAY_ORDER
				) LOOP
			IF l_record.DISPLAY_ORDER = 1 THEN
				t_output := t_output || chr(10) || l_record.SUBMISSION_DATE::text;
			END IF;

			t_output := t_output || '|' || coalesce(l_record.COUNT, 0);
		END LOOP;

	ELSIF t_type = 'mozilla-certvalidations-by-owner' THEN
		t_outputType := 'csv';
		t_output := 'Date';
		FOR l_record IN (
					SELECT coalesce(replace(mrh.CA_OWNER, chr(10), ', '), 'UNKNOWN') CA_OWNER
						FROM mozilla_root_hashes mrh
							LEFT OUTER JOIN ccadb_certificate cc ON (mrh.CERTIFICATE_ID = cc.CERTIFICATE_ID)
						WHERE mrh.DISPLAY_ORDER IS NOT NULL
						GROUP BY mrh.CA_OWNER
						ORDER BY min(mrh.DISPLAY_ORDER)
				) LOOP
			t_output := t_output || '|' || coalesce(l_record.CA_OWNER, 'UNKNOWN');
		END LOOP;

		t_temp := '';
		FOR l_record IN (
					SELECT coalesce(replace(mrh.CA_OWNER, chr(10), ', '), 'UNKNOWN') CA_OWNER, min(mrh.DISPLAY_ORDER) DISPLAY_ORDER, mcvs.SUBMISSION_DATE, sum(mcvs.COUNT) COUNT
						FROM mozilla_cert_validation_success mcvs, mozilla_root_hashes mrh
							LEFT OUTER JOIN ccadb_certificate cc ON (mrh.CERTIFICATE_ID = cc.CERTIFICATE_ID)
						WHERE mcvs.BIN_NUMBER = mrh.BIN_NUMBER
							AND mrh.DISPLAY_ORDER IS NOT NULL
						GROUP BY mrh.CA_OWNER, mcvs.SUBMISSION_DATE
						ORDER BY mcvs.SUBMISSION_DATE, min(mrh.DISPLAY_ORDER)
				) LOOP
			IF l_record.DISPLAY_ORDER = 1 THEN
				t_output := t_output || chr(10) || l_record.SUBMISSION_DATE::text;
			END IF;

			t_output := t_output || '|' || coalesce(l_record.COUNT, 0);
		END LOOP;

	ELSIF t_type = 'mozilla-certvalidations-by-version' THEN
		t_certificateID := coalesce(get_parameter('id', paramNames, paramValues), '0')::bigint;
		t_outputType := 'csv';
		t_output := 'Date';

		SELECT array_agg(sub.RELEASE_VERSION)
			INTO t_versions
			FROM (
				SELECT (mcvsi.RELEASE || '/' || mcvsi.VERSION) RELEASE_VERSION
					FROM mozilla_root_hashes mrh, mozilla_cert_validation_success_import mcvsi
					WHERE mrh.CERTIFICATE_ID = t_certificateID
						AND mrh.BIN_NUMBER = mcvsi.BIN_NUMBER
					GROUP BY mcvsi.RELEASE, mcvsi.VERSION
					ORDER BY mcvsi.RELEASE, mcvsi.VERSION::integer
			) sub;
		FOR i IN 1..array_length(t_versions, 1) LOOP
			t_output := t_output || '|' || t_versions[i];
		END LOOP;

		t_date := '2000-01-01'::date;
		t_pos1 := array_length(t_versions, 1);
		FOR l_record IN (
					SELECT mcvsi.SUBMISSION_DATE, mcvsi.COUNT, (mcvsi.RELEASE || '/' || mcvsi.VERSION) RELEASE_VERSION
						FROM mozilla_root_hashes mrh, mozilla_cert_validation_success_import mcvsi
						WHERE mrh.CERTIFICATE_ID = t_certificateID
							AND mrh.BIN_NUMBER = mcvsi.BIN_NUMBER
						ORDER BY mcvsi.SUBMISSION_DATE, mcvsi.RELEASE, mcvsi.VERSION::integer
				) LOOP
			IF l_record.SUBMISSION_DATE > t_date THEN
				WHILE t_pos1 < array_length(t_versions, 1) LOOP
					t_output := t_output || '|0';
					t_pos1 := t_pos1 + 1;
				END LOOP;
				t_date := l_record.SUBMISSION_DATE;
				t_output := t_output || chr(10) || l_record.SUBMISSION_DATE::text;
				t_pos1 := 1;
			END IF;

			WHILE l_record.RELEASE_VERSION != t_versions[t_pos1] LOOP
				t_output := t_output || '|0';
				t_pos1 := t_pos1 + 1;
			END LOOP;
			t_pos1 := t_pos1 + 1;

			t_output := t_output || '|' || coalesce(l_record.COUNT, 0);
		END LOOP;
		WHILE t_pos1 < array_length(t_versions, 1) LOOP
			t_output := t_output || '|X';
			t_pos1 := t_pos1 + 1;
		END LOOP;

	ELSIF t_type = 'mozilla-certvalidations' THEN
		t_certificateID := get_parameter('id', paramNames, paramValues)::bigint;
		t_temp := '';
		IF t_certificateID IS NOT NULL THEN
			t_temp := 'id=' || t_certificateID::text;
		END IF;
		IF coalesce(t_groupBy, 'root') NOT IN ('owner', 'version') THEN
			t_groupBy := 'root';
		END IF;
		t_output := t_output ||
'  <SPAN class="whiteongrey">Mozilla Certificate Validations</SPAN>';
		IF t_groupBy IN ('owner', 'version') THEN
			t_output := t_output || '
&nbsp; &nbsp; &nbsp; <A style="font-size:8pt" href="?group=root">Group by Root</A>';
		END IF;
		IF t_groupBy IN ('root', 'version') THEN
			t_output := t_output || '
&nbsp; &nbsp; &nbsp; <A style="font-size:8pt" href="?group=owner">Group by Owner</A>';
		END IF;
		t_output := t_output || '
  <BR><SPAN class="small"><A href="//mzl.la/2nvPgJs" target="_blank">CERT_VALIDATION_SUCCESS_BY_CA telemetry</A> for ';
		IF t_groupBy IN ('owner', 'root') THEN
			t_output := t_output || 'all Firefox Beta versions';
		ELSE
			SELECT get_ca_name_attribute(cac.CA_ID)
				INTO t_temp2
				FROM ca_certificate cac
				WHERE cac.CERTIFICATE_ID = t_certificateID;
			t_output := t_output || '<B>' || t_temp2 || '</B>';
		END IF;
		t_output := t_output || '</SPAN>
<BR><BR>
<DIV id="root" style="text-align:left;font:8pt Roboto;font-weight:normal">
  <DIV id="spinner" style="margin:0 auto;width:400px;padding-top:70px;"><IMG src="/spinner.gif" style="display:inline-block" /><SPAN style="font-size:20px;display:inline-block;position:relative;top:-52px;left:30px">Loading...</SPAN></DIV>
  <DIV id="graph" class="many" style="width:100%"></DIV>
  <DIV id="options">
    <BUTTON onclick="toggleAll(true)">Select All</BUTTON>
    <BUTTON onclick="toggleAll(false)">Deselect All</BUTTON>
  </DIV>
  <DIV style="height:400px;width:500px;overflow:auto"><FORM id="graph_toggles"></FORM></DIV>
  <DIV id="graph_labels" style="text-align:left"></DIV>
</DIV>
<SCRIPT type="text/javascript">
  var graph = new Dygraph(
    document.getElementById("graph"),
    "/mozilla-certvalidations-by-' || t_groupBy || '?' || t_temp || '", {
    axes: {
      x: {
        drawGrid: false
      },
      y: {
        drawAxis: true,
        drawGrid: true
      }
    },
    connectSeparatedPoints: true,
    delimiter: ''|'',
    highlightCircleSize: 2,
    highlightSeriesOpts: {
      strokeWidth: 2,
      strokeBorderWidth: 1,
      highlightCircleSize: 3
    },
    includeZero: true,
    panEdgeFraction: 0.1,
    strokeBorderWidth: 1,
    strokeWidth: 1,
    labelsKMB: true,
    xRangePad: 50
  });

  var onclick = function(ev) {
    if (graph.isSeriesLocked()) {
      graph.clearSelection();
    } else {
      graph.setSelection(graph.getSelection(), graph.getHighlightSeries(), true);
    }
  };
  graph.updateOptions({clickCallback: onclick}, true);

  graph.ready(function() {
    document.getElementById("spinner").style.display = "none";

    var toggles_form = document.getElementById("graph_toggles");
    var labels = graph.getLabels();
    var colors = graph.getColors();
    for (var i = 1; i < labels.length; ++i) {
      (function(series) {
        var label_elt = document.createElement("label");
        label_elt.style.color = colors[series];
        var checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.onclick = function () {
          graph.setVisibility(series, this.checked);
        };
        checkbox.checked = true;
        label_elt.appendChild(checkbox);
        var label_span = document.createElement("span");
        label_span.innerHTML = " " + labels[series + 1];
        label_elt.appendChild(label_span);

        toggles_form.appendChild(label_elt);
      })(i - 1);
    }
  });

  function toggleAll(clicked) {
    var w = document.getElementsByTagName(''input'');
    for(var i = 0; i < w.length; i++) {
      if ((w[i].type == ''checkbox'') && (w[i].checked != clicked)) {
        w[i].click();
      }
    }
  }
</SCRIPT>
';

	ELSIF t_type = 'mozilla-disclosures' THEN
		t_output := t_output || mozilla_disclosures();

	ELSIF t_type = 'mozilla-onecrl' THEN
		t_output := t_output ||
'  <SPAN class="whiteongrey">Mozilla OneCRL</SPAN>
<BR><SPAN class="small">Generated at ' || TO_CHAR(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH style="white-space:nowrap">crt.sh ID</TH>
    <TH>Created</TH>
    <TH>Last Modified</TH>
    <TH>Summary</TH>
    <TH>Bug</TH>
    <TH>Serial Number</TH>
    <TH>Issuer Name</TH>
    <TH>Subject Name</TH>
    <TH>Not After</TH>
  </TR>
';
	FOR l_record IN (
				SELECT mo.CERTIFICATE_ID, mo.CREATED, mo.LAST_MODIFIED, mo.SUMMARY, mo.BUG_URL, mo.SERIAL_NUMBER,
						mo.ISSUER_CA_ID, x509_name_print(mo.ISSUER_NAME) ISSUER_NAME_TEXT,
						x509_name_print(mo.SUBJECT_NAME) SUBJECT_NAME_TEXT, mo.NOT_AFTER
					FROM mozilla_onecrl mo
					ORDER BY mo.LAST_MODIFIED DESC NULLS FIRST, mo.SUMMARY, mo.BUG_URL, ISSUER_NAME_TEXT, mo.SERIAL_NUMBER
			) LOOP
		t_output := t_output ||
'  <TR>
    <TD>';
		IF l_record.CERTIFICATE_ID IS NOT NULL THEN
			t_output := t_output || '<A href="/?id=' || l_record.CERTIFICATE_ID::text || '" target="_blank">' || coalesce(l_record.CERTIFICATE_ID::text, '') || '</A>';
		ELSE
			t_output := t_output || '&nbsp;';
		END IF;
		t_output := t_output || '</TD>
    <TD style="white-space:nowrap">' || coalesce(TO_CHAR(l_record.CREATED, 'YYYY-MM-DD'), 'Unspecified') || '</TD>
    <TD style="white-space:nowrap">' || coalesce(TO_CHAR(l_record.LAST_MODIFIED, 'YYYY-MM-DD'), 'Unspecified') || '</TD>
    <TD>' || coalesce(l_record.SUMMARY, '&nbsp;')|| '</TD>
    <TD><A href="' || l_record.BUG_URL || '" target="_blank">' || substring(l_record.BUG_URL from '[0-9]*$') || '</A></TD>
    <TD>' || coalesce(encode(l_record.SERIAL_NUMBER, 'hex'), '&nbsp;') || '</TD>
    <TD>';
		IF l_record.ISSUER_CA_ID IS NOT NULL THEN
			t_output := t_output || '<A href="/?caID=' || l_record.ISSUER_CA_ID::text || '" style="white-space:normal" target="_blank">';
		END IF;
		t_output := t_output || coalesce(l_record.ISSUER_NAME_TEXT, '&nbsp;');
		IF l_record.ISSUER_CA_ID IS NOT NULL THEN
			t_output := t_output || '</A>';
		END IF;
		t_output := t_output || '</TD>
    <TD>' || coalesce(l_record.SUBJECT_NAME_TEXT, '&nbsp;') || '</TD>
    <TD style="white-space:nowrap">' || coalesce(TO_CHAR(l_record.NOT_AFTER, 'YYYY-MM-DD'), '&nbsp;') || '</TD>
  </TR>
';
	END LOOP;
	t_output := t_output ||
'</TABLE>
';

	ELSIF t_type = 'microsoft-disclosures' THEN
		t_output := t_output || microsoft_disclosures();

	ELSIF t_type = 'apple-disclosures' THEN
		t_output := t_output || apple_disclosures();

	ELSIF t_type = 'ca-issuers' THEN
		t_cacheControlMaxAge := -1;
		IF get_parameter('webpki', paramNames, paramValues) IS NOT NULL THEN
			t_output := t_output || ca_issuers(
				'v', 2, NULL, NULL, NULL, NULL, NULL, 'Server Authentication', 'expired,onecrl,crlset,disallowedstl'
			);
		ELSE
			t_output := t_output || ca_issuers(
				coalesce(get_parameter('dir', paramNames, paramValues), 'v'),
				coalesce(get_parameter('sort', paramNames, paramValues), '2')::integer,
				get_parameter('rootOwner', paramNames, paramValues),
				get_parameter('url', paramNames, paramValues),
				get_parameter('content', paramNames, paramValues),
				get_parameter('contentType', paramNames, paramValues),
				get_parameter('trustedby', paramNames, paramValues),
				get_parameter('trustedfor', paramNames, paramValues),
				get_parameter('trustedexclude', paramNames, paramValues)
			);
		END IF;

	ELSIF t_type = 'ocsp-responders' THEN
		t_cacheControlMaxAge := -1;
		IF get_parameter('webpki', paramNames, paramValues) IS NOT NULL THEN
			t_output := t_output || ocsp_responders(
				'v', 2, NULL, NULL, 'Server Authentication', 'expired,onecrl,crlset,disallowedstl', NULL, NULL, NULL, NULL, NULL, NULL, NULL
			);
		ELSE
			t_output := t_output || ocsp_responders(
				coalesce(get_parameter('dir', paramNames, paramValues), 'v'),
				coalesce(get_parameter('sort', paramNames, paramValues), '2')::integer,
				get_parameter('url', paramNames, paramValues),
				get_parameter('trustedby', paramNames, paramValues),
				get_parameter('trustedfor', paramNames, paramValues),
				get_parameter('trustedexclude', paramNames, paramValues),
				get_parameter('get', paramNames, paramValues),
				get_parameter('post', paramNames, paramValues),
				get_parameter('getrandomserial', paramNames, paramValues),
				coalesce(
					get_parameter('postrandomserial', paramNames, paramValues),
					get_parameter('randomserial', paramNames, paramValues)
				),
				get_parameter('getforwardslashes', paramNames, paramValues),
				get_parameter('getunencodedplus', paramNames, paramValues),
				get_parameter('getsha256certid', paramNames, paramValues)
			);
		END IF;

	ELSIF t_type = 'ocsp-response' THEN
		t_cacheControlMaxAge := -1;
		t_output := t_output || ocsp_response(
			coalesce(get_parameter('caID', paramNames, paramValues), '')::integer,
			coalesce(get_parameter('url', paramNames, paramValues), ''),
			coalesce(get_parameter('request', paramNames, paramValues), ''),
			coalesce(get_parameter('type', paramNames, paramValues), 'dump')
		);

	ELSIF t_type = 'test-websites' THEN
		t_cacheControlMaxAge := -1;
		t_output := t_output || test_websites(
			coalesce(get_parameter('dir', paramNames, paramValues), 'v'),
			coalesce(get_parameter('sort', paramNames, paramValues), '2')::integer,
			get_parameter('trustedby', paramNames, paramValues)
		);

	ELSIF t_type IN (
				'ID',
				'SHA-1(Certificate)',
				'SHA-256(Certificate)',
				'Certificate ASN.1',
				'Certification Graph',
				'PKI Hierarchy',
				'pv-certificate-viewer'
			)
			OR (
				(lower(',' || t_opt) LIKE '%,firstresult,%')
				AND (t_type = 'Serial Number')
			) THEN
		t_output := t_output ||
' <SPAN class="whiteongrey">Certificate Search</SPAN>
<BR><BR>
';

		t_certSummary := 'Leaf certificate';

		-- Search for a specific Certificate.
		IF t_type IN ('ID', 'Certificate ASN.1', 'Certification Graph', 'PKI Hierarchy', 'pv-certificate-viewer') THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					x509_rsamodulus(c.CERTIFICATE),
					x509_hasROCAFingerprint(c.CERTIFICATE),
					x509_hasClosePrimes(c.CERTIFICATE),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_rsaModulus,
					t_hasROCAFingerprint,
					t_hasClosePrimes,
					t_certificate
				FROM certificate c
					LEFT OUTER JOIN ca ON (c.ISSUER_CA_ID = ca.ID)
					LEFT OUTER JOIN ca_certificate cac ON (c.ID = cac.CERTIFICATE_ID)
				WHERE c.ID = t_value::bigint;
		ELSIF t_type = 'SHA-1(Certificate)' THEN
			SELECT c.ID, x509_print(c.CERTIFICATE, NULL, 196608), ca.ID, cac.CA_ID,
					digest(c.CERTIFICATE, 'sha1'::text),
					digest(c.CERTIFICATE, 'sha256'::text),
					x509_serialNumber(c.CERTIFICATE),
					digest(x509_publicKey(c.CERTIFICATE), 'sha256'::text),
					x509_rsamodulus(c.CERTIFICATE),
					x509_hasROCAFingerprint(c.CERTIFICATE),
					x509_hasClosePrimes(c.CERTIFICATE),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_rsaModulus,
					t_hasROCAFingerprint,
					t_hasClosePrimes,
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
					x509_rsamodulus(c.CERTIFICATE),
					x509_hasROCAFingerprint(c.CERTIFICATE),
					x509_hasClosePrimes(c.CERTIFICATE),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_rsaModulus,
					t_hasROCAFingerprint,
					t_hasClosePrimes,
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
					x509_rsamodulus(c.CERTIFICATE),
					x509_hasROCAFingerprint(c.CERTIFICATE),
					x509_hasClosePrimes(c.CERTIFICATE),
					c.CERTIFICATE
				INTO t_certificateID, t_text, t_issuerCAID, t_caID,
					t_certificateSHA1,
					t_certificateSHA256,
					t_serialNumber,
					t_spkiSHA256,
					t_rsaModulus,
					t_hasROCAFingerprint,
					t_hasClosePrimes,
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
						|| t_temp || '">Issuer:</A> <SPAN class="small">(CA ID: ' || t_issuerCAID::text || ')</SPAN><BR>'
			);
		END IF;
		IF x509_notAfter(t_certificate) < now() AT TIME ZONE 'UTC' THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Validity<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Validity <SPAN class="small">(Expired)</SPAN><BR>'
			);
		ELSIF x509_notBefore(t_certificate) > now() AT TIME ZONE 'UTC' THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Validity<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Validity <SPAN class="small">(Not Yet Valid)</SPAN><BR>'
			);
		END IF;
		IF t_caID IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Subject:<BR>',
				'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?caid='
						|| t_caID::text
						|| t_temp || '">Subject:</A> <SPAN class="small">(CA ID: ' || t_caID::text || ')</SPAN><BR>'
			);
			IF t_caID = coalesce(t_issuerCAID, -1) THEN
				t_certSummary := 'Root certificate';
			ELSE
				t_certSummary := 'Intermediate certificate';
			END IF;
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
		t_bytea := x509_authorityKeyId(t_certificate);
		IF t_bytea IS NOT NULL THEN
			t_text := replace(
				t_text, '<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;X509v3&nbsp;Authority&nbsp;Key&nbsp;Identifier:&nbsp;<BR>',
					'<BR>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<A href="?ski='
							|| coalesce(encode(t_bytea, 'hex'), '')
							|| '">X509v3&nbsp;Authority&nbsp;Key&nbsp;Identifier:</A><BR>'
			);
		END IF;

		t_offset := strpos(t_text, 'CT&nbsp;Precertificate');
		IF t_offset != 0 THEN
			IF substr(t_text, t_offset, 34) = 'CT&nbsp;Precertificate&nbsp;Poison' THEN
				t_certSummary := 'Precertificate';
			END IF;
			SELECT c.ID::text
				INTO t_temp
				FROM certificate c
				WHERE x509_serialNumber(c.certificate) = t_serialNumber
					AND c.ISSUER_CA_ID = t_issuerCAID
					AND c.ID != t_certificateID;
			IF t_temp IS NOT NULL THEN
				IF t_certSummary = 'Precertificate' THEN
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
    <TH class="outer">Summary</TH>
    <TD class="outer">' || t_certSummary || '</TD>
  </TR>
  <TR>
    <TH class="outer">Certificate Transparency</TH>
    <TD class="outer">
      <DIV style="overflow-y:scroll;height:100px">
        <TABLE style="margin-left:0px">
          <TR>
            <TD>
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
						|| to_char(l_record.ENTRY_TIMESTAMP, 'HH24:MI:SS UTC')
						|| '</FONT></TD>
    <TD>' || l_record.ENTRY_ID::text || '</TD>
    <TD>' || html_escape(l_record.OPERATOR) || '</TD>
    <TD>' || html_escape(l_record.URL) || '</TD>
  </TR>
';
			END LOOP;
			IF t_temp = '' THEN
				t_temp := '  <TR><TD colspan="4">No entries found</TD></TR>';
			END IF;
			t_output := t_output ||
'<TABLE class="options" style="margin-left:0px">
  <TR>
    <TD colspan="4" style="border:none"><I>Log entries for this certificate:</I></TD>
  </TR>
  <TR>
    <TH>Timestamp</TH>
    <TH>Entry #</TH>
    <TH>Log Operator</TH>
    <TH>Log URL</TH>
  </TR>
' || t_temp ||
'</TABLE>
            </TD>
';

			IF t_caID = coalesce(t_issuerCAID, -1) THEN
				t_output := t_output ||
'            <TD style="border:none;width:15px"></TD>
            <TD>
';
				t_temp := '';
				FOR l_record IN (
					SELECT ctl.CHROME_INCLUSION_STATUS, ctl.APPLE_INCLUSION_STATUS, ctl.OPERATOR, ctl.URL
						FROM accepted_roots ar, ct_log ctl
						WHERE ar.CERTIFICATE_ID = t_certificateID
							AND ar.CT_LOG_ID = ctl.ID
							AND ctl.IS_ACTIVE
						ORDER BY
							CASE coalesce(ctl.CHROME_INCLUSION_STATUS, '')
								WHEN 'Usable' THEN 1
								WHEN '' THEN 3
								ELSE 2
							END,
							CASE coalesce(ctl.APPLE_INCLUSION_STATUS, '')
								WHEN 'Usable' THEN 1
								WHEN '' THEN 3
								ELSE 2
							END,
							ctl.OPERATOR, ctl.URL
				) LOOP
					t_temp := t_temp ||
'  <TR>
    <TD>' || coalesce(l_record.CHROME_INCLUSION_STATUS, '&nbsp;') || '</TD>
    <TD>' || coalesce(l_record.APPLE_INCLUSION_STATUS, '&nbsp;') || '</TD>
    <TD>' || coalesce(l_record.OPERATOR, '&nbsp;') || '</TD>
    <TD>' || l_record.URL || '</TD>
  </TR>
';
				END LOOP;
				IF t_temp = '' THEN
					t_temp := '  <TR><TD colspan="4">No logs found</TD></TR>';
				END IF;
				t_output := t_output ||
'<TABLE class="options" style="margin-left:0px">
  <TR>
    <TD colspan="4" style="border:none"><I>Active Logs for which this certificate is an Accepted Root Certificate:</I></TD>
  </TR>
  <TR>
    <TH>Chromium Status</TH>
    <TH>Apple Status</TH>
    <TH>Log Operator</TH>
    <TH>Log URL</TH>
  </TR>
  ' || t_temp || '
</TABLE>
            </TD>
';
			END IF;

			t_output := t_output ||
'            <TD style="border:none;width:15px"></TD>
          </TR>
        </TABLE>
      </DIV>
    </TD>
  </TR>
';

			IF t_caID IS NOT NULL THEN
				t_output := t_output ||
'  <TR>
    <TH class="outer">Audit details<BR>
      <DIV class="small" style="padding-top:3px">Disclosed via the
        <A href="//ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCerts" target="_blank">CCADB</A></DIV>
    </TH>
    <TD class="outer">
';
				t_temp := NULL;
				t_temp2 := NULL;
				FOR l_record IN (
							SELECT *
								FROM ccadb_certificate cc
								WHERE cc.CCADB_RECORD_ID IS NOT NULL
									AND cc.CERTIFICATE_ID = t_certificateID
						) LOOP
					IF t_temp IS NULL THEN
						t_temp :=
'<TABLE class="options" style="margin-left:0px">
  <TR>
    <TH>Auditor</TH>
    <TH>Standard Audit</TH>
    <TH>BR Audit</TH>
    <TH>EV SSL Audit</TH>
    <TH>Documents</TH>
    <TH>CCADB</TH>
    <TH>Owner / Certificate</TH>
  </TR>
';
					END IF;
					t_temp := t_temp ||
'  <TR>
    <TD style="vertical-align:middle">' || coalesce(l_record.AUDITOR, '') || '</TD>
    <TD style="vertical-align:middle">' || coalesce(l_record.STANDARD_AUDIT_TYPE, 'Not disclosed');
					IF coalesce(l_record.STANDARD_AUDIT_URL, '') LIKE '%://%' THEN
						t_temp := t_temp || ':
      <A href="' || l_record.STANDARD_AUDIT_URL || '" target="_blank">' || coalesce(l_record.STANDARD_AUDIT_DATE::text, 'Yes') || '</A>
      <BR><FONT style="font-size:8pt">(' || l_record.STANDARD_AUDIT_START || ' to ' || l_record.STANDARD_AUDIT_END || ')</FONT></TD>
';
					END IF;
					t_temp := t_temp ||
'    <TD style="vertical-align:middle">' || coalesce(l_record.BRSSL_AUDIT_TYPE, 'No');
					IF coalesce(l_record.BRSSL_AUDIT_URL, '') LIKE '%://%' THEN
						t_temp := t_temp || ':
      <A href="' || l_record.BRSSL_AUDIT_URL || '" target="_blank">' || coalesce(l_record.BRSSL_AUDIT_DATE::text, 'Yes') || '</A>
      <BR><FONT style="font-size:8pt">(' || l_record.BRSSL_AUDIT_START || ' to ' || l_record.BRSSL_AUDIT_END || ')</FONT></TD>
';
					END IF;
					t_temp := t_temp ||
'    <TD style="vertical-align:middle">' || coalesce(l_record.EVSSL_AUDIT_TYPE, 'No');
					IF coalesce(l_record.EVSSL_AUDIT_URL, '') LIKE '%://%' THEN
						t_temp := t_temp || ':
      <A href="' || l_record.EVSSL_AUDIT_URL || '" target="_blank">' || coalesce(l_record.EVSSL_AUDIT_DATE::text, 'Yes') || '</A>
      <BR><FONT style="font-size:8pt">(' || l_record.EVSSL_AUDIT_START || ' to ' || l_record.EVSSL_AUDIT_END || ')</FONT></TD>
';
					END IF;
					t_temp := t_temp ||
'    <TD style="vertical-align:middle">
';
					FOREACH t_temp3 IN ARRAY string_to_array(coalesce(l_record.CP_URL, ''), '; ') LOOP
						t_temp := t_temp ||
'      <A href="' || t_temp3 || '" target="blank">CP</A>
';
					END LOOP;
					FOREACH t_temp3 IN ARRAY string_to_array(coalesce(l_record.CPS_URL, ''), '; ') LOOP
						t_temp := t_temp ||
'      <A href="' || t_temp3 || '" target="blank">CPS</A>
';
					END LOOP;
					t_temp := t_temp ||
'    </TD>
    <TD style="vertical-align:middle">';
					IF l_record.CCADB_RECORD_ID IS NOT NULL THEN
						t_temp := t_temp || '<A href="//ccadb.my.site.com/' || l_record.CCADB_RECORD_ID || '" target="_blank">' || l_record.CCADB_RECORD_ID || '</A>';
					ELSE
						t_temp := t_temp || '&nbsp;';
					END IF;
					t_temp := t_temp || '</TD>
    <TD style="vertical-align:middle">';
					IF l_record.INCLUDED_CERTIFICATE_ID IS NULL THEN
						t_temp := t_temp || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;');
					ELSE
						t_temp := t_temp || '<A href="/?id=' || l_record.INCLUDED_CERTIFICATE_ID::text || '">Root</A> CA: ' || coalesce(html_escape(l_record.INCLUDED_CERTIFICATE_OWNER), '&nbsp;') || '
      <BR>This CA: ' || coalesce(html_escape(coalesce(nullif(trim(l_record.SUBORDINATE_CA_OWNER), ''), l_record.INCLUDED_CERTIFICATE_OWNER)), '&nbsp;');
					END IF;
					t_temp := t_temp || '</TD>
  </TR>
';
					IF l_record.CERT_RECORD_TYPE = 'Root Certificate' THEN
						t_temp2 :=
'  <TR>
    <TH class="outer">Telemetry<BR>
      <DIV class="small" style="padding-top:3px">Collected by
        <A href="//mzl.la/2nvPgJs" target="_blank">Mozilla</A></DIV>
    </TH>
    <TD class="outer"><A href="mozilla-certvalidations?group=version&id=' || t_certificateID::text || '" target="_blank">CERT_VALIDATION_SUCCESS_BY_CA</A></TD>
  </TR>
';
					END IF;
				END LOOP;
				IF t_temp IS NOT NULL THEN
					t_temp := t_temp ||
'</TABLE>';
				ELSE
					t_temp := 'Not Disclosed';
				END IF;

				t_output := t_output || t_temp || '
    </TD>
  </TR>
' || coalesce(t_temp2, '');
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
					|| '</SPAN></TD><TD>'
					|| to_char(cr.REVOCATION_DATE, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
					|| to_char(cr.REVOCATION_DATE, 'HH24:MI:SS UTC') || '</FONT></TD><TD>'
					|| to_char(cr.LAST_SEEN_CHECK_DATE, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
					|| to_char(cr.LAST_SEEN_CHECK_DATE, 'HH24:MI:SS UTC') || '</FONT>'
				INTO t_temp0
				FROM crl_revoked cr
				WHERE cr.CA_ID = t_issuerCAID
					AND cr.SERIAL_NUMBER = t_serialNumber;
			t_count := 1;
			IF NOT FOUND THEN
				SELECT count(*)
					INTO t_count
					FROM crl
					WHERE crl.CA_ID = t_issuerCAID
						AND crl.ERROR_MESSAGE IS NULL
						AND crl.NEXT_UPDATE > now() AT TIME ZONE 'UTC';
				IF t_count > 0 THEN
					t_temp0 := 'Not Revoked';
				ELSE
					t_temp0 := '<SPAN style="color:#FF9400">Unknown</SPAN>';
				END IF;
				IF x509_notAfter(t_certificate) < now() AT TIME ZONE 'UTC' THEN
					t_temp0 := t_temp0 || ' (Expired)';
				END IF;
				t_temp0 := t_temp0 || '</TD><TD><SPAN style="color:#888888">n/a</SPAN></TD><TD><SPAN style="color:#888888">n/a</SPAN>';
			END IF;

			SELECT to_char(max(crl.LAST_CHECKED), 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
					|| to_char(max(crl.LAST_CHECKED), 'HH24:MI:SS UTC') || '</FONT>'
				INTO t_temp
				FROM crl
				WHERE crl.CA_ID = t_issuerCAID;
			t_temp0 := t_temp0 || '</TD><TD>' || coalesce(t_temp, '');
			IF t_count = 0 THEN
				SELECT array_to_string(array_agg('<FONT color="#CC0000">' || html_escape(crl.ERROR_MESSAGE) || '</FONT> [' || html_escape(crl.DISTRIBUTION_POINT_URL || ']')), '<BR>')
					INTO t_temp
					FROM crl
					WHERE crl.CA_ID = t_issuerCAID
						AND crl.ERROR_MESSAGE IS NOT NULL;
				IF t_temp IS NOT NULL THEN
					t_temp0 := t_temp0 || '<BR><SPAN style="vertical-align:middle;font-size:70%">' || coalesce(t_temp, '') || '</SPAN>';
				END IF;
			END IF;

			SELECT '<SPAN style="color:#CC0000">Revoked [by ' || gr.ENTRY_TYPE || ']</SPAN>'
				INTO t_temp
				FROM google_revoked gr
				WHERE gr.CERTIFICATE_ID = t_certificateID;
			t_temp := coalesce(t_temp, 'Not Revoked');

			SELECT '<SPAN style="color:#CC0000">Revoked' ||
					CASE length(mdc.DISALLOWED_HASH)
						WHEN 16 THEN ' [by MD5(PublicKey)]'
						WHEN 48 THEN ' [by SHA-384(TBSCertificate)]'
					END || '</SPAN>'
				INTO t_temp2
				FROM microsoft_disallowedcert mdc
				WHERE mdc.CERTIFICATE_ID = t_certificateID;
			t_temp2 := coalesce(t_temp2, 'Not Revoked');

			SELECT '<SPAN style="color:#CC0000">Revoked [by ' || mo.ENTRY_TYPE::text || ']</SPAN></TD><TD>'
					|| CASE WHEN mo.CREATED IS NOT NULL
						THEN to_char(mo.CREATED, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
							|| to_char(mo.CREATED, 'HH24:MI:SS UTC') || '</FONT>'
						ELSE '<SPAN style="color:#888888">Unknown</SPAN>'
						END
				INTO t_temp3
				FROM mozilla_onecrl mo
				WHERE mo.CERTIFICATE_ID = t_certificateID;
			t_temp3 := coalesce(t_temp3, 'Not Revoked</TD><TD><SPAN style="color:#888888">n/a</SPAN>');

			IF lower(',' || t_opt) LIKE '%,ocsp,%' THEN
				SELECT coalesce(c2.CERTIFICATE, c1.CERTIFICATE)
					INTO t_issuerCertificate
					FROM ca_certificate cac1, certificate c1
						LEFT JOIN LATERAL (
							SELECT c2.CERTIFICATE
								FROM ca_certificate cac2, certificate c2
								WHERE cac2.CA_ID = c1.ISSUER_CA_ID
									AND cac2.CERTIFICATE_ID = c2.ID
									AND EXISTS (SELECT 1 FROM x509_extKeyUsages(c1.CERTIFICATE) WHERE x509_extKeyUsages = '1.3.6.1.4.1.11129.2.4.4')
								LIMIT 1
						) c2 ON TRUE
					WHERE cac1.CA_ID = t_issuerCAID
						AND cac1.CERTIFICATE_ID = c1.ID
					LIMIT 1;
				t_temp4 := ocsp_embedded(t_certificate, t_issuerCertificate);
				IF t_temp4 LIKE 'Good%' THEN
					t_temp4 := 'Good</TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>';
				ELSIF t_temp4 LIKE 'Revoked%' THEN
					t_offset := position('|' in t_temp4);
					t_pos1 := position('|' in substring(t_temp4 from t_offset + 1)) + t_offset;
					t_temp5 := '<SPAN style="color:#CC0000">Revoked' || CASE substring(t_temp4 from (t_pos1 + 1))::integer
						WHEN 1 THEN ' (keyCompromise)'
						WHEN 2 THEN ' (cACompromise)'
						WHEN 3 THEN ' (affiliationChanged)'
						WHEN 4 THEN ' (superseded)'
						WHEN 5 THEN ' (cessationOfOperation)'
						WHEN 6 THEN ' (certificateHold)'
						WHEN 7 THEN ' (privilegeWithdrawn)'
						WHEN 8 THEN ' (aACompromise)'
						ELSE ''
					END || '</SPAN>';
					t_temp4 := t_temp5 || '</TD>
          <TD>' || to_char(substring(t_temp4 from (t_offset + 1) for 19)::timestamp, 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
				|| to_char(substring(t_temp4 from (t_offset + 1) for 19)::timestamp, 'HH24:MI:SS UTC') || '</FONT></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>';
				ELSIF t_temp4 LIKE 'Unknown%' THEN
					t_temp4 := '<SPAN style="color:#FF9400">Unknown</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>';
				ELSE	-- "No OCSP URL Available" or error.
					t_temp4 := t_temp4 || '</TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>';
				END IF;
				t_temp4 := t_temp4 || '
          <TD>' || to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD') || '&nbsp; <FONT class="small">'
				|| to_char(now() AT TIME ZONE 'UTC', 'HH24:MI:SS UTC') || '</FONT>';
			ELSE
				t_temp4 := '<A href="?id=' || t_certificateID::text || '&opt=' || t_opt || 'ocsp">Check</A></TD>
          <TD><SPAN style="color:#888888">?</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">?</SPAN>';
			END IF;

			t_output := t_output ||
'  <TR>
    <TH class="outer">Revocation';
			IF lower(',' || t_opt) NOT LIKE '%,problemreporting,%' THEN
				t_output := t_output || '<BR><BR>
      <DIV class="small" style="padding-top:3px"><A href="?id=' || t_certificateID::text || '&opt=problemreporting">Report a problem</A> with<BR>this certificate to the CA</DIV>';
			END IF;
			t_output := t_output || '</TH>
    <TD class="outer">
      <TABLE class="options" style="margin-left:0px">
        <TR>
          <TH>Mechanism</TH>
          <TH>Provider</TH>
          <TH>Status</TH>
          <TH>Revocation Date</TH>
          <TH>Last Observed in CRL</TH>
          <TH>Last Checked <SPAN style="color:#CC0000;vertical-align:middle;font-size:70%;font-weight:normal">(Error)</SPAN></TH>
        </TR>
        <TR>
          <TD>OCSP</TD>
          <TD>The CA</TD>
          <TD>' || t_temp4 || '</TD>
        </TR>
        <TR>
          <TD>CRL</TD>
          <TD>The CA</TD>
          <TD>' || t_temp0 || '</TD>
        </TR>
        <TR>
          <TD>CRLSet/Blocklist</TD>
          <TD>Google</TD>
          <TD>' || t_temp || '</TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
        </TR>
        <TR>
          <TD>disallowedcert.stl</TD>
          <TD>Microsoft</TD>
          <TD>' || t_temp2 || '</TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
        </TR>
        <TR>
          <TD><A href="/mozilla-onecrl" target="_blank">OneCRL</A></TD>
          <TD>Mozilla</TD>
          <TD>' || t_temp3 || '</TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
          <TD><SPAN style="color:#888888">n/a</SPAN></TD>
        </TR>
      </TABLE>
    </TD>
  </TR>
';
			IF lower(',' || t_opt) LIKE '%,problemreporting,%' THEN
				SELECT cco.PROBLEM_REPORTING
					INTO t_temp3
					FROM ca_certificate cac, ccadb_certificate cc, ccadb_caowner cco, ca_trust_purpose ctp, certificate c
					WHERE cac.CA_ID = t_issuerCAID
						AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
						AND cc.INCLUDED_CERTIFICATE_OWNER = cco.CA_OWNER_NAME
						AND cac.CA_ID = ctp.CA_ID
						AND cac.CERTIFICATE_ID = c.ID
					GROUP BY cco.PROBLEM_REPORTING
					ORDER BY min(ctp.SHORTEST_CHAIN), max(x509_notAfter(c.CERTIFICATE)) DESC
					LIMIT 1;

				IF trim(coalesce(t_temp3, '')) = '' THEN
					t_temp3 := 'Unknown';
				END IF;
				t_output := t_output ||
'  <TR>
    <TH class="outer">Problem Reporting<BR>
      <DIV class="small" style="padding-top:3px">Mechanism(s) disclosed<BR>via the
        <A href="//ccadb.my.salesforce-sites.com/mozilla/CAInformationReport" target="_blank">CCADB</A></DIV>
    </TH>
    <TD class="outer">' || replace(html_escape(t_temp3), '. ', '.<BR>') || '</TD>
  </TR>
';
			END IF;
		END IF;

		t_output := t_output ||
'  <TR>
    <TH class="outer">Certificate Fingerprints</TH>
    <TD class="outer">
      <TABLE class="options" style="margin-left:0px">
        <TR>
          <TH>SHA-256</TH>
          <TD><A href="//search.censys.io/certificates/' || coalesce(lower(encode(t_certificateSHA256, 'hex')), '') || '">'
						|| coalesce(upper(encode(t_certificateSHA256, 'hex')), '<I>Not found</I>') || '</A></TD>
          <TD style="width:20px;border:none">&nbsp;</TD>
          <TH>SHA-1</TH>
          <TD>' || coalesce(upper(encode(t_certificateSHA1, 'hex')), '<I>Not found</I>') || '</TD>
        </TR>
      </TABLE>
    </TD>
  </TR>
';

		t_showCABLint := (',' || t_opt) LIKE '%,cablint,%';
		IF t_showCABLint THEN
			t_output := t_output ||
'  <TR>
    <TH class="outer">CA/B Forum lint<BR>
      <DIV class="small" style="padding-top:3px">Powered by <A href="//github.com/certlint/certlint" target="_blank">certlint</A></DIV>
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

		t_showZLint := (',' || t_opt) LIKE '%,zlint,%';
		IF t_showZLint THEN
			t_output := t_output ||
'  <TR>
    <TH class="outer">ZLint<BR>
      <DIV class="small" style="padding-top:3px">Powered by <A href="//github.com/zmap/zlint" target="_blank">zlint</A></DIV>
    </TH>
    <TD class="text">
';
			FOR l_record IN (
						SELECT substr(ZLINT, 4) ISSUE_TEXT,
								CASE substr(ZLINT, 1, 2)
									WHEN 'B:' THEN 1
									WHEN 'I:' THEN 2
									WHEN 'N:' THEN 3
									WHEN 'F:' THEN 4
									WHEN 'E:' THEN 5
									WHEN 'W:' THEN 6
									ELSE 5
								END ISSUE_TYPE,
								CASE substr(ZLINT, 1, 2)
									WHEN 'B:' THEN '<SPAN>&nbsp; &nbsp; &nbsp;BUG:'
									WHEN 'I:' THEN '<SPAN>&nbsp; &nbsp; INFO:'
									WHEN 'N:' THEN '<SPAN class="notice">&nbsp; NOTICE:'
									WHEN 'F:' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
									WHEN 'E:' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
									WHEN 'W:' THEN '<SPAN class="warning">&nbsp;WARNING:'
									ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || substr(ZLINT, 1, 2)
								END ISSUE_HEADING
							FROM zlint_embedded(t_certificate) ZLINT
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

		SELECT '<SPAN class="error">Debian OpenSSL RNG vulnerability</SPAN> <SPAN class="small"><A href="//en.wikipedia.org/wiki/Random_number_generator_attack#Debian_OpenSSL" target="_blank">Details</A></SPAN>'
			INTO t_publicKeyProblems
			FROM debian_weak_key dwk
			WHERE dwk.SHA1_MODULUS = digest('Modulus=' || upper(encode(t_rsaModulus, 'hex')) || chr(10), 'sha1');
		IF t_hasROCAFingerprint THEN
			IF t_publicKeyProblems IS NOT NULL THEN
				t_publicKeyProblems := t_publicKeyProblems || '<BR>';
			END IF;
			t_publicKeyProblems := coalesce(t_publicKeyProblems, '') || '<SPAN class="error">ROCA vulnerability</SPAN> <SPAN class="small"><A href="//en.wikipedia.org/wiki/ROCA_vulnerability" target="_blank">Details</A></SPAN>';
		END IF;
		IF t_hasClosePrimes THEN
			IF t_publicKeyProblems IS NOT NULL THEN
				t_publicKeyProblems := t_publicKeyProblems || '<BR>';
			END IF;
			t_publicKeyProblems := coalesce(t_publicKeyProblems, '') || '<SPAN class="error">Close Primes vulnerability</SPAN> <SPAN class="small"><A href="//crypto.stackexchange.com/questions/5262/rsa-and-prime-difference" target="_blank">Details</A></SPAN>';
		END IF;

		IF t_publicKeyProblems IS NOT NULL THEN
			t_output := t_output ||
'  <TR>
    <TH class="outer">Public Key Problems</TH>
    <TD class="text">' || t_publicKeyProblems || '</TD>
  </TR>
';
		END IF;

		t_output := t_output ||
'  <TR>
';

		IF t_type = 'Certificate ASN.1' THEN
			t_action := 'asn1';
			t_output := t_output ||
'    <TH class="outer" style="white-space:nowrap">
      | ASN.1 |
      <A href="?id=' || t_certificateID::text || '">Certificate</A> |
      <A href="?graph=' || t_certificateID::text || '&opt=nometadata">Graph</A> |<BR>
      | <A href="?h=' || t_certificateID::text || '&opt=nometadata">Hierarchy</A> |
      <A href="?pv=' || t_certificateID::text || '">pv</A> |
      <BR><BR><SPAN class="small">Powered by <A href="//lapo.it/asn1js/" target="_blank">asn1js</A><BR>
';
		ELSIF t_type = 'Certification Graph' THEN
			t_action := 'graph';
			t_output := t_output ||
'    <TH class="outer" style="white-space:nowrap">
      | <A href="?asn1=' || t_certificateID::text || '">ASN.1</A> |
      <A href="?id=' || t_certificateID::text || '">Certificate</A> |
      Graph |<BR>
      | <A href="?h=' || t_certificateID::text || '&opt=nometadata">Hierarchy</A> |
      <A href="?pv=' || t_certificateID::text || '">pv</A> |
      <BR><BR><SPAN class="small">Powered by <A href="//js.cytoscape.org/" target="_blank">Cytoscape.js</A> <A href="//github.com/cytoscape/cytoscape.js-dagre">and</A> <A href="//github.com/dagrejs/dagre">Dagre</A><BR>
';
		ELSIF t_type = 'PKI Hierarchy' THEN
			t_action := 'h';
			t_output := t_output ||
'    <TH class="outer" style="white-space:nowrap">
      | <A href="?asn1=' || t_certificateID::text || '">ASN.1</A> |
      <A href="?id=' || t_certificateID::text || '">Certificate</A> |
      <A href="?graph=' || t_certificateID::text || '&opt=nometadata">Graph</A> |<BR>
      | Hierarchy |
      <A href="?pv=' || t_certificateID::text || '">pv</A> |
      <SPAN class="small"><BR>
';
		ELSIF t_type = 'pv-certificate-viewer' THEN
			t_action := 'pv';
			t_output := t_output ||
'    <TH class="outer" style="white-space:nowrap">
      | <A href="?asn1=' || t_certificateID::text || '">ASN.1</A> |
      <A href="?id=' || t_certificateID::text || '">Certificate</A> |
      <A href="?graph=' || t_certificateID::text || '&opt=nometadata">Graph</A> |<BR>
      | <A href="?h=' || t_certificateID::text || '&opt=nometadata">Hierarchy</A> |
      pv
      <BR><BR><SPAN class="small">Powered by <A href="//github.com/PeculiarVentures/pv-certificates-viewer" target="_blank">pv-certificates-viewer</A> |<BR>
';
		ELSE
			t_action := 'id';
			t_output := t_output ||
'    <TH class="outer" style="white-space:nowrap">
      | <A href="?asn1=' || t_certificateID::text || '">ASN.1</A> |
      Certificate |
      <A href="?graph=' || t_certificateID::text || '&opt=nometadata">Graph</A> |<BR>
      | <A href="?h=' || t_certificateID::text || '&opt=nometadata">Hierarchy</A> |
      <A href="?pv=' || t_certificateID::text || '">pv</A> |
      <SPAN class="small"><BR>
';
		END IF;

		IF t_showMetadata THEN
			t_output := t_output ||
'      <BR><BR><A href="?' || t_action || '=' || t_certificateID::text || '&opt=' || t_opt || 'nometadata">Hide metadata</A>
';
		ELSE
			IF t_opt = 'nometadata,' THEN
				t_temp := '';
			ELSE
				t_temp := '&opt=' || rtrim(replace(t_opt, 'nometadata,', ''), ',');
			END IF;
			t_output := t_output ||
'      <BR><BR><A href="?' || t_action || '=' || t_certificateID::text || t_temp || '">Show metadata</A>
';
		END IF;
		IF NOT t_showCABLint THEN
			t_output := t_output ||
'      <BR><BR><A href="?' || t_action || '=' || t_certificateID::text || '&opt=' || t_opt || 'cablint">Run cablint</A>
';
		END IF;
		IF NOT t_showX509Lint THEN
			t_output := t_output ||
'      <BR><BR><A href="?' || t_action || '=' || t_certificateID::text || '&opt=' || t_opt || 'x509lint">Run x509lint</A>
';
		END IF;
		IF NOT t_showZLint THEN
			t_output := t_output ||
'      <BR><BR><A href="?' || t_action || '=' || t_certificateID::text || '&opt=' || t_opt || 'zlint">Run zlint</A>
';
		END IF;
		t_output := t_output ||
'      <BR><BR><BR>Download Certificate: <A href="?d=' || t_certificateID::text || '">PEM</A>
      </SPAN>
    </TH>
';

		IF t_type = 'Certificate ASN.1' THEN
			t_output := t_output ||
'    <TD class="text" style="width:100%">
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
		ELSIF t_type = 'Certification Graph' THEN
			t_output := t_output ||
'    <TD style="width:100%">
      <DIV id="spinner" style="margin:0 auto;width:400px;padding-top:70px;"><IMG src="/spinner.gif" style="display:inline-block" /><SPAN style="font-size:20px;display:inline-block;position:relative;top:-52px;left:30px">Loading...</SPAN></DIV>
      <BR><DIV id="cy"></DIV>
      <SCRIPT type="text/javascript">
$.ajax({
  dataType: "json",
  url: "?nodes=' || t_certificateID::text || '",
  success: function(data) {
    var cy = window.cy = cytoscape({
      container: $("#cy"),

      boxSelectionEnabled: true,
      autounselectify: true,
      userPanningEnabled: true,
      userZoomingEnabled: true,
      fit: true,

      layout: {
        name: "dagre",
        rankDir: "TB",
        stop: function() { document.getElementById("spinner").style.display = "none"; }
      },
      style: cytoscape.stylesheet()
        .selector("node").css({
          "content": "",
          "background-color": "data(color)",
          "color": "#000",
          "shape": "data(type)",
          "label": "data(label)",
          "text-halign": "center",
          "text-valign": "center",
          "text-wrap": "wrap",
          "text-max-width": "50px",
          "font-family": "Roboto",
          "font-weight": "400",
          "font-size": "8pt",
          "width": "50px",
          "height": "50px"
        })
        .selector(":selected").css({
          "border-width": 3,
          "border-color": "#333"
        })
        .selector("edge").css({
          "curve-style": "bezier",
          "color": "data(color)",
          "line-color": "data(linecolor)",
          "target-arrow-color": "data(linecolor)",
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.75,
          "label": "data(label)",
          "width": 1,
          "edge-text-rotation": "autorotate",
          "font-size": "8pt"
        }),
      elements: data["elements"],
    });
    cy.on("tap", "edge", function(){
      if (this.data("href")) {
        try { // your browser may block popups
          window.open( this.data("href") );
        } catch(e){ // fall back on url change
          window.location.href = this.data("href");
        }
      }
    }); 
    cy.on("tap", "node", function(){
      if (this.data("href")) {
        try { // your browser may block popups
          window.open( this.data("href") );
        } catch(e){ // fall back on url change
          window.location.href = this.data("href");
        }
      }
    }); 
  },
});
      </SCRIPT>
';
		ELSIF t_type = 'PKI Hierarchy' THEN
			t_output := t_output ||
'    <TD style="padding:5px 20px">
      <TABLE style="width:100%;border:0px;margin-right:0px">
        <TR style="border:0px">
          <TD style="border:0px">' || pki_hierarchy(t_certificateID, t_excludeExpired IS NOT NULL) || '</TD>
          <TD style="border:0px">
            <DIV>
              <FONT style="color:#00CC00">Valid</FONT>
              <BR><FONT style="color:#CC0000;font-style:italic;text-decoration:line-through">Revoked by CRL</FONT>
              <BR><FONT style="color:#888888;font-style:italic;text-decoration:line-through">Expired; was observed as Revoked</FONT>
              <BR><FONT style="color:#888888">Expired</FONT>
              <BR><FONT style="color:#00007F"><B>[External Operator]</B></FONT>
              <BR><BR><BR><A href="/?h=' || t_certificateID::text;
			IF coalesce(t_opt, '') != '' THEN
				t_output := t_output || '&opt=' || rtrim(t_opt, ',');
			END IF;
			IF t_excludeExpired IS NULL THEN
				t_output := t_output || '&exclude=expired">Hide expired certificates?</A>';
			ELSE
				t_output := t_output || '">Show expired certificates?</A>';
			END IF;
			t_output := t_output || '
            </DIV>
          </TD>
        </TR>
      </TABLE>
    </TD>';
		ELSIF t_type = 'pv-certificate-viewer' THEN
			t_output := t_output ||
'    <TD>
      <peculiar-certificate-viewer
        certificate="' || replace(encode(t_certificate, 'base64'), chr(10), '') || '"
        issuer-dn-link="?caid=' || t_issuerCAID::text || '"
        auth-key-id-parent-link="?ski={{authKeyId}}"
        subject-key-id-siblings-link="?ski={{subjectKeyId}}"
      />
';
		ELSE
			t_output := t_output ||
'    <TD class="text">' || coalesce(t_text, '<I>Not found</I>');
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
			t_useReverseIndex := (
				position('%' IN t_value) < position('%' IN reverse(t_value))
			);
		END IF;

		t_output := t_output ||
'<TABLE>
  <TR>
    <TH class="outer">Criteria</TH>
    <TD class="outer">Type: ' || html_escape(t_type)
						|| '&nbsp;&nbsp;&nbsp;&nbsp;Match: ' || html_escape(t_match)
						|| '&nbsp;&nbsp;&nbsp;&nbsp;Search: ' || ' ''' || html_escape(t_value) || '''</TD>
  </TR>
</TABLE>
<BR>
';

		-- Search for a specific CA.
		IF t_type = 'CA ID' THEN
			SELECT ca.ID, ca.NAME, ca.PUBLIC_KEY, ca.NUM_ISSUED, ca.NUM_EXPIRED
				INTO t_caID, t_caName, t_caPublicKey, t_numIssued, t_numExpired
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
						SELECT cc.MOZILLA_DISCLOSURE_STATUS
							INTO t_temp2
							FROM ccadb_certificate cc
							WHERE cc.CERTIFICATE_ID = l_record.ID;
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
							SELECT sum(ls.NO_OF_CERTS) NUM_CERTS, li.ID, li.SEVERITY, li.ISSUE_TEXT,
									CASE li.SEVERITY
										WHEN 'F' THEN 1
										WHEN 'E' THEN 2
										WHEN 'W' THEN 3
										ELSE 4
									END ISSUE_TYPE,
									CASE li.SEVERITY
										WHEN 'F' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
										WHEN 'E' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
										WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
										ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || li.SEVERITY || ':'
									END ISSUE_HEADING
								FROM lint_summary ls, lint_issue li
								WHERE ls.NOT_BEFORE_DATE >= t_minNotBefore
									AND ls.ISSUER_CA_ID = t_value::integer
									AND ls.LINT_ISSUE_ID = li.ID
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
							SELECT sum(ls.NO_OF_CERTS) NUM_CERTS, li.ID, li.SEVERITY, li.ISSUE_TEXT,
									CASE li.SEVERITY
										WHEN 'F' THEN 1
										WHEN 'E' THEN 2
										WHEN 'W' THEN 3
										ELSE 4
									END ISSUE_TYPE,
									CASE li.SEVERITY
										WHEN 'F' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
										WHEN 'E' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
										WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
										ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || li.SEVERITY || ':'
									END ISSUE_HEADING
								FROM lint_summary ls, lint_issue li
								WHERE ls.NOT_BEFORE_DATE >= t_minNotBefore
									AND ls.ISSUER_CA_ID = t_value::integer
									AND ls.LINT_ISSUE_ID = li.ID
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

			t_showZLint := (',' || coalesce(get_parameter('opt', paramNames, paramValues), '') || ',') LIKE '%,zlint,%';
			IF t_showZLint THEN
				t_output := t_output ||
'  <TR>
    <TH class="outer">ZLint</TH>
    <TD class="outer">
      <TABLE class="options">
        <TR><TH colspan=3>For Issued Certificates with notBefore >= ' || to_char(t_minNotBefore, 'YYYY-MM-DD') || ':</TH><TR>
        <TR>
          <TH>Issue</TH>
          <TH># Affected Certs</TH>
        </TR>
';
				FOR l_record IN (
							SELECT sum(ls.NO_OF_CERTS) NUM_CERTS, li.ID, li.SEVERITY, li.ISSUE_TEXT,
									CASE li.SEVERITY
										WHEN 'F' THEN 1
										WHEN 'E' THEN 2
										WHEN 'W' THEN 3
										ELSE 4
									END ISSUE_TYPE,
									CASE li.SEVERITY
										WHEN 'F' THEN '<SPAN class="fatal">&nbsp; &nbsp;FATAL:'
										WHEN 'E' THEN '<SPAN class="error">&nbsp; &nbsp;ERROR:'
										WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
										ELSE '<SPAN>&nbsp; &nbsp; &nbsp; &nbsp;' || li.SEVERITY || ':'
									END ISSUE_HEADING
								FROM lint_summary ls, lint_issue li
								WHERE ls.NOT_BEFORE_DATE >= t_minNotBefore
									AND ls.ISSUER_CA_ID = t_value::integer
									AND ls.LINT_ISSUE_ID = li.ID
									AND li.LINTER = 'zlint'
								GROUP BY li.ID, li.SEVERITY, li.ISSUE_TEXT
								ORDER BY ISSUE_TYPE, NUM_CERTS DESC
						) LOOP
					t_output := t_output ||
'        <TR>
          <TD class="text">' || l_record.ISSUE_HEADING || ' ' || l_record.ISSUE_TEXT || '&nbsp;</SPAN></TD>
          <TD><A href="?zlint=' || l_record.ID::text || '&iCAID=' || t_caID::text || t_minNotBeforeString || '">' || l_record.NUM_CERTS::text || '</A></TD>
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
            t_url = "//search.censys.io/certificates-legacy?q="
                   + encodeURIComponent("parsed.issuer_dn=\"' || replace(t_caName, '"', '') || '\"");
            var t_field = "";
            if (value != "%") {
              if (type == "Identity") {
                t_url += " AND (parsed.names:" + encodeURIComponent("\"" + value + "\"") + ")";
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
            with (document.search_form) {
              if (match.options[match.selectedIndex].value != "")
                t_url += "&match=" + match.options[match.selectedIndex].value;
            }
            if (document.search_form.deduplicate.checked)
              t_url += "&deduplicate=Y";
            if (document.search_form.showSQL.checked)
              t_url += "&showSQL=Y";
          }
          window.location = t_url;
        }
      </SCRIPT>
      <FORM name="search_form" method="GET" onSubmit="return false">
        <INPUT type="hidden" name="caID" value="' || t_caID::text || '">
        <TABLE class="options" style="margin-left:0px">
          <TR>
            <TD class="options" style="padding-right:20px;vertical-align:top">
              <TABLE class="options" style="margin-left:0px">
                <TR>
                  <TH>Population</TH>
                  <TD style="text-align:center">Unexpired</TD>
                  <TD style="text-align:center">Expired</TD>
                  <TD style="text-align:center">TOTAL</TD>
                </TR>
                <TR>
                  <TD style="text-align:center">Certificates</TD>
                  <TD style="text-align:right">' || (coalesce(t_numIssued[1], 0) - coalesce(t_numExpired[1], 0))::text || '</TD>
                  <TD style="text-align:right">' || coalesce(t_numExpired[1], 0)::text || '</TD>
                  <TD style="text-align:right">' || coalesce(t_numIssued[1], 0)::text || '</TD>
                </TR>
                <TR>
                  <TD style="text-align:center">Precertificates</TD>
                  <TD style="text-align:right">' || (coalesce(t_numIssued[2], 0) - coalesce(t_numExpired[2], 0))::text || '</TD>
                  <TD style="text-align:right">' || coalesce(t_numExpired[2], 0)::text || '</TD>
                  <TD style="text-align:right">' || coalesce(t_numIssued[2], 0)::text || '</TD>
                </TR>
                <TR>
                  <TD style="text-align:center">TOTAL</TD>
                  <TD style="text-align:right">' || ((coalesce(t_numIssued[1], 0) - coalesce(t_numExpired[1], 0) + coalesce(t_numIssued[2], 0)) - coalesce(t_numExpired[2], 0))::text || '</TD>
                  <TD style="text-align:right">' || (coalesce(t_numExpired[1], 0) + coalesce(t_numExpired[2], 0))::text || '</TD>
                  <TD style="text-align:right">' || (coalesce(t_numIssued[1], 0) + coalesce(t_numIssued[2], 0))::text || '</TD>
                </TR>
              </TABLE>
            </TD>
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
              <SPAN class="text">Enter search term:</SPAN><BR><SPAN class="small">(% = All certificates)</SPAN>
              <BR><BR>
              <INPUT type="text" name="idvalue" class="input" size="25" style="margin-top:2px">
              <BR><BR><BR>
              <INPUT type="submit" class="button" value="Search"
                     onClick="identitySearch(document.search_form.idtype.value,document.search_form.idvalue.value)">
            </TD>
            <TD class="options" style="padding-left:20px;vertical-align:top">
              <SPAN class="text">Search options:</SPAN>
              <BR><BR><DIV style="border:1px solid #AAAAAA;margin-bottom:5px;padding:4px 2px;text-align:left">
                &nbsp;<SELECT name="match">
                  <OPTION value="" selected>Autoselect</OPTION>
                  <OPTION value="=">=</OPTION>
                  <OPTION value="ILIKE">ILIKE</OPTION>
                  <OPTION value="LIKE">LIKE</OPTION>
                  <OPTION value="single">Single</OPTION>
                  <OPTION value="any">Any</OPTION>
                  <OPTION value="FTS">Full Text Search</OPTION>
                </SELECT> Identity matching
                <BR><INPUT type="checkbox" name="excludeExpired"';
			IF t_excludeExpired IS NOT NULL THEN
				t_output := t_output || ' checked';
			END IF;
			t_output := t_output || '> Exclude expired certificates?
                <BR><INPUT type="checkbox" name="deduplicate"';
			IF t_deduplicate THEN
				t_output := t_output || ' checked';
			END IF;
			t_output := t_output || '> Deduplicate (pre)certificate pairs?
                <BR><INPUT type="checkbox" name="showSQL"';
			IF t_showSQL THEN
				t_output := t_output || ' checked';
			END IF;
			t_output := t_output || '> Show SQL?
                <HR>
                &nbsp;Or, <INPUT type="checkbox" name="searchCensys"';
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
'          <TH colspan="' || t_count::text || '">Context <SPAN class="small">(Version)</SPAN> <SPAN style="vertical-align:super;font-size:70%"><FONT style="color:#33A8FF">Shortest Path</FONT> &nbsp;<FONT style="color:#9100FF">Disabled From</FONT> &nbsp;<FONT style="color:#FF9100">NotBefore Until</FONT></SPAN></TH>
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
								ctp.ALL_CHAINS_TECHNICALLY_CONSTRAINED,
								ctp.DISABLED_FROM,
								ctp.NOTBEFORE_UNTIL
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
				IF (t_purposeOID != l_record.PURPOSE_OID) OR (t_purpose != l_record.PURPOSE) THEN
					t_purposeOID := l_record.PURPOSE_OID;
					t_purpose := l_record.PURPOSE;
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
							AND ctp.TRUST_PURPOSE_ID = 1
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
					t_text := t_text || 'CC0000 style="font-weight:bold">Revoked</FONT> <FONT style="font-size:8pt;color:#CC0000">via<BR>CRLSet / Blocklist';
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
				IF l_record.DISABLED_FROM IS NOT NULL THEN
					t_text := t_text || '<BR><SPAN style="font-size:70%;color:#9100FF">' || l_record.DISABLED_FROM::date || '</SPAN>';
				END IF;
				IF l_record.NOTBEFORE_UNTIL IS NOT NULL THEN
					t_text := t_text || '<BR><SPAN style="font-size:70%;color:#FF9100">' || l_record.NOTBEFORE_UNTIL::date || '</SPAN>';
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
				WITH child_certificate AS MATERIALIZED (
					SELECT c.ID, x509_subjectName(c.CERTIFICATE) SUBJECT_NAME
						FROM certificate c
						WHERE c.ISSUER_CA_ID = t_caID
							AND x509_canIssueCerts(c.CERTIFICATE)
				)
				SELECT child_certificate.SUBJECT_NAME,
						cac.CA_ID
					FROM child_certificate,
						ca_certificate cac
							LEFT OUTER JOIN ca ON (cac.CA_ID = ca.ID)
					WHERE child_certificate.ID = cac.CERTIFICATE_ID
						AND cac.CA_ID != t_caID
					GROUP BY child_certificate.SUBJECT_NAME, cac.CA_ID
					ORDER BY child_certificate.SUBJECT_NAME
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
				'ZLint',
				'keylint',
				'Lint'
			) THEN
		IF length(t_value) = 1 THEN
			NULL;
		ELSIF (substr(t_value, 1, 1) = '%') AND (substr(t_value, length(t_value), 1) = '%') THEN
			t_value := substr(t_value, 2, length(t_value) - 2);
		ELSIF substr(t_value, 1, 2) = '%.' THEN
			t_value := substr(t_value, 3);
		ELSIF position('%' in t_value) = length(t_value) THEN
			IF t_value LIKE '% %' THEN
				t_value := substr(t_value, 1, length(t_value) - 1);
			ELSE
				t_value := substr(t_value, 1, length(t_value) - 1) || ':*';
				t_match := 'FTS';
				t_tsqueryFunction := 'to_tsquery';
			END IF;
		ELSIF position('%' in t_value) > 0 THEN
			RAISE no_data_found USING MESSAGE = 'Unsupported use of ''%''';
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
    <TD class="outer">Type: ' || html_escape(t_type)
						|| '&nbsp;&nbsp;&nbsp;&nbsp;Match: ' || html_escape(t_match) || '&nbsp;&nbsp;&nbsp;&nbsp;Search: ';
			IF lower(t_type) LIKE '%lint' THEN
				SELECT CASE li.SEVERITY
							WHEN 'F' THEN '<SPAN class="fatal">&nbsp;FATAL:'
							WHEN 'E' THEN '<SPAN class="error">&nbsp;ERROR:'
							WHEN 'W' THEN '<SPAN class="warning">&nbsp;WARNING:'
							ELSE '<SPAN>&nbsp;' || li.SEVERITY || ':'
						END || ' ' || li.ISSUE_TEXT || '&nbsp;</SPAN>'
					INTO t_temp
					FROM lint_issue li
					WHERE li.ID = t_value::integer
						AND li.LINTER = coalesce(t_linter, li.LINTER);
				t_output := t_output || t_temp;
			ELSE
				t_output := t_output || '''' || html_escape(t_value) || '''';
			END IF;
			IF t_caID IS NOT NULL THEN
				t_output := t_output || '&nbsp;&nbsp;&nbsp;&nbsp;Issuer CA ID: ' || t_caID::text;
			END IF;
			IF t_excludeExpired IS NOT NULL THEN
				t_output := t_output || '&nbsp;&nbsp;&nbsp;&nbsp;Exclude expired certificates';
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
			t_temp := NULL;
			IF (t_value = '%') OR t_type IN (
				'Serial Number', 'Subject Key Identifier',
				'SHA-1(SubjectPublicKeyInfo)', 'SHA-256(SubjectPublicKeyInfo)', 'SHA-1(Subject)'
			) THEN
				t_match := NULL;
				t_query :=
						'SELECT c.ID,' || chr(10) ||
						'       c.ISSUER_CA_ID,' || chr(10) ||
						'       x509_subjectName(c.CERTIFICATE) SUBJECT_NAME,' || chr(10) ||
						'       x509_notBefore(c.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
						'       x509_notAfter(c.CERTIFICATE) NOT_AFTER,' || chr(10) ||
						'       encode(x509_serialNumber(c.CERTIFICATE), ''hex'') SERIAL_NUMBER' || chr(10) ||
						'    FROM certificate c' || chr(10) ||
						'    WHERE c.ISSUER_CA_ID = $1::integer' || chr(10);
				IF t_type = 'Serial Number' THEN
					t_query := t_query ||
						'        AND x509_serialNumber(c.CERTIFICATE) = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'Subject Key Identifier' THEN
					t_query := t_query ||
						'        AND x509_subjectKeyIdentifier(c.CERTIFICATE) = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
					t_query := t_query ||
						'        AND digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-256(SubjectPublicKeyInfo)' THEN
					t_query := t_query ||
						'        AND digest(x509_publickey(c.CERTIFICATE), ''sha256'') = decode($2, ''hex'')' || chr(10);
				ELSIF t_type = 'SHA-1(Subject)' THEN
					t_query := t_query ||
						'        AND digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($2, ''hex'')' || chr(10);
				END IF;
			ELSIF lower(t_type) LIKE '%lint' THEN
				t_query :=
						'SELECT c.ID,' || chr(10) ||
						'       c.ISSUER_CA_ID,' || chr(10) ||
						'       x509_subjectName(c.CERTIFICATE) SUBJECT_NAME,' || chr(10) ||
						'       x509_notBefore(c.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
						'       x509_notAfter(c.CERTIFICATE) NOT_AFTER,' || chr(10) ||
						'       encode(x509_serialNumber(c.CERTIFICATE), ''hex'') SERIAL_NUMBER' || chr(10) ||
						'    FROM certificate c,' || chr(10) ||
						'         lint_cert_issue lci, lint_issue li' || chr(10) ||
						'    WHERE c.ISSUER_CA_ID = $1::integer' || chr(10) ||
						'        AND c.ID = lci.CERTIFICATE_ID' || chr(10) ||
						'        AND lci.ISSUER_CA_ID = $1::integer' || chr(10) ||
						'        AND lci.NOT_BEFORE_DATE >= $3' || chr(10) ||
						'        AND lci.LINT_ISSUE_ID = $2::integer' || chr(10) ||
						'        AND lci.LINT_ISSUE_ID = li.ID' || chr(10);
				IF t_linter IS NOT NULL THEN
					t_query := t_query ||
						'        AND li.LINTER = ''' || t_linter || '''' || chr(10);
				END IF;
			ELSE
				t_query :=
						'WITH ci AS MATERIALIZED (' || chr(10) ||
						'    SELECT sub.CERTIFICATE_ID ID,' || chr(10) ||
						'           sub.ISSUER_CA_ID,' || chr(10) ||
						'           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,' || chr(10) ||
						'           x509_subjectName(sub.CERTIFICATE) SUBJECT_NAME,' || chr(10) ||
						'           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
						'           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,' || chr(10) ||
						'           encode(x509_serialNumber(sub.CERTIFICATE), ''hex'') SERIAL_NUMBER' || chr(10) ||
						'        FROM (SELECT *' || chr(10) ||
						'                  FROM certificate_and_identities cai' || chr(10) ||
						'                  WHERE ' || t_tsqueryFunction || '(''certwatch'', $2) @@ identities(cai.CERTIFICATE)' || chr(10);
				IF t_match = 'Single' THEN
					t_query := t_query ||
						'                      AND plainto_tsquery(''certwatch'', $2) @@ to_tsvector(''certwatch'', cai.NAME_VALUE)' || chr(10);
				ELSIF t_match = 'FTS' THEN
					t_query := t_query ||
						'                      AND to_tsquery(''certwatch'', $2) @@ to_tsvector(''certwatch'', cai.NAME_VALUE)' || chr(10);
				ELSIF t_match != 'Any' THEN
					t_query := t_query ||
						'                      AND cai.NAME_VALUE ' || t_match || ' ';
					IF t_match != '=' THEN
						t_query := t_query || '(''%'' || ';
					END IF;
					t_query := t_query || '$2';
					IF t_match != '=' THEN
						t_query := t_query || ' || ''%'')';
					END IF;
					t_query := t_query || chr(10);
				END IF;
				IF t_type != 'Identity' THEN
					t_query := t_query ||
						'                      AND cai.NAME_TYPE = ' || quote_literal(t_nameType_oid) || ' -- ' || t_nameType || chr(10);
				END IF;
				IF t_excludeExpired IS NOT NULL THEN
					t_query := t_query ||
						'                      AND coalesce(x509_notAfter(cai.CERTIFICATE), ''infinity''::timestamp) >= date_trunc(''year'', now() AT TIME ZONE ''UTC'')' || chr(10) ||
						'                      AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE ''UTC''' || chr(10);
					t_temp := t_excludeExpired;
				END IF;
				IF t_deduplicate THEN
					t_query := t_query ||
						'                      AND NOT EXISTS (' || chr(10) ||
						'                          SELECT 1' || chr(10) ||
						'                              FROM certificate c2' || chr(10) ||
						'                              WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)' || chr(10) ||
						'                                  AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID' || chr(10) ||
						'                                  AND c2.ID < cai.CERTIFICATE_ID' || chr(10) ||
						'                                  AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)' || chr(10) ||
						'                              LIMIT 1' || chr(10) ||
						'                      )' || chr(10);
				END IF;
				t_query := t_query ||
						'                  LIMIT 10000' || chr(10) ||
						'             ) sub' || chr(10) ||
						'    GROUP BY sub.CERTIFICATE_ID, sub.ISSUER_CA_ID, sub.CERTIFICATE' || chr(10) ||
						')' || chr(10) ||
						'SELECT ci.ID,' || chr(10) ||
						'       ci.ISSUER_CA_ID,' || chr(10) ||
						'       array_to_string(ci.NAME_VALUES, chr(10)) NAME_VALUE,' || chr(10) ||
						'       ci.SUBJECT_NAME,' || chr(10) ||
						'       ci.NOT_BEFORE,' || chr(10) ||
						'       ci.NOT_AFTER,' || chr(10) ||
						'       ci.SERIAL_NUMBER' || chr(10) ||
						'    FROM ci' || chr(10) ||
						'    WHERE ci.ISSUER_CA_ID = $1' || chr(10);
			END IF;

			IF (t_excludeExpired IS NOT NULL) AND (t_temp IS NULL) THEN
				t_query := t_query ||
   						'        AND coalesce(x509_notAfter(c.CERTIFICATE), ''infinity''::timestamp) >= date_trunc(''year'', now() AT TIME ZONE ''UTC'')' || chr(10) ||
						'        AND x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE ''UTC''' || chr(10);
			END IF;
			IF lower(t_type) LIKE '%lint' THEN
				t_query := t_query ||
						'    GROUP BY c.ID, c.ISSUER_CA_ID, SUBJECT_NAME, NOT_BEFORE, NOT_AFTER, SERIAL_NUMBER' || chr(10);
			END IF;
			t_query := t_query ||
						'    ORDER BY NOT_BEFORE DESC';
			IF t_pageNo IS NOT NULL THEN
				t_query := t_query || chr(10) ||
						'    OFFSET ' || ((t_pageNo - 1) * t_resultsPerPage)::text || chr(10) ||
						'    LIMIT ' || t_resultsPerPage::text;
			END IF;

			t_showIdentity := (t_match NOT IN ('=', 'Any')) OR (t_type = 'CT Entry ID');

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
    <TD style="white-space:nowrap">' || coalesce(to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD'), '&nbsp;') || '</TD>
    <TD style="white-space:nowrap">' || coalesce(to_char(l_record.NOT_AFTER, 'YYYY-MM-DD'), '&nbsp;') || '</TD>
';
				IF t_showIdentity THEN
					t_text := t_text ||
'    <TD>' || replace(html_escape(l_record.NAME_VALUE), chr(10), '<BR>') || '</TD>
';
				END IF;
				t_text := t_text ||
'    <TD>' || coalesce(html_escape(l_record.SUBJECT_NAME), '&nbsp;') || '</TD>
  </TR>
';
			END LOOP;

			IF t_pageNo IS NOT NULL THEN
				IF (t_value = '%') AND (t_excludeExpired IS NULL) THEN
					SELECT coalesce(ca.NUM_ISSUED[1], 0) + coalesce(ca.NUM_ISSUED[2], 0)
						INTO t_count
						FROM ca
						WHERE ca.ID = t_caID;
				ELSE
					t_temp := 'SELECT count(*) FROM (' || chr(10) || substring(t_query from '^.*    ORDER BY');
					t_temp := substr(t_temp, 1, length(t_temp) - length('    ORDER BY')) || ') sub';
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
									urlEncode(t_cmd) || '=' || urlEncode(t_value) ||
									'&iCAID=' || t_caID::text || coalesce(t_excludeExpired, '') ||
									'&p=' || (t_pageNo - 1)::text ||
									'&n=' || t_resultsPerPage::text || '">Previous</A> &nbsp; ';
					END IF;
					t_output := t_output || '<B>' ||
								(((t_pageNo - 1) * t_resultsPerPage) + 1)::integer || '</B> to <B>' ||
								least(t_pageNo * t_resultsPerPage, t_count)::integer || '</B>';
					IF (t_pageNo * t_resultsPerPage) < t_count THEN
						t_output := t_output || ' &nbsp; <A style="font-size:8pt" href="?' ||
									urlEncode(t_cmd) || '=' || urlEncode(t_value) ||
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
';
				IF t_showIdentity THEN
					t_output := t_output ||
'    <TH>Matching&nbsp;Identities</TH>
';
				END IF;
				t_output := t_output ||
'    <TH>Subject Name</TH>
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

			t_needMinEntryTimestamp := TRUE;

			t_select :=		'SELECT __issuer_ca_id_table__.ISSUER_CA_ID,' || chr(10) ||
							'        ca.NAME ISSUER_NAME,__common_name_field__' || chr(10) ||
							'        __name_value__ NAME_VALUE,' || chr(10);
			t_from := 		'    FROM ';
			t_where := '';
			IF coalesce(t_groupBy, '') = 'none' THEN
				t_select := t_select ||
							'        __cert_id_field__ ID,' || chr(10) ||
							'        __entry_timestamp_field__,' || chr(10) ||
							'        __not_before_field__,' || chr(10) ||
							'        __not_after_field__,' || chr(10) ||
							'        __serial_number_field__';
				t_notBefore_field := 'x509_notBefore(c.CERTIFICATE) NOT_BEFORE';
				t_notAfter_field := 'x509_notAfter(c.CERTIFICATE) NOT_AFTER';
				t_serialNumber_field := 'encode(x509_serialNumber(c.CERTIFICATE), ''hex'') SERIAL_NUMBER';

				t_query :=	'    ORDER BY ';
				IF t_sort = 0 THEN
					t_query := t_query || 'ID ' || t_orderBy;
				ELSIF t_sort = 1 THEN
					t_query := t_query || '__entry_timestamp_field__ ' || t_orderBy || ' NULLS LAST';
				ELSIF t_sort = 2 THEN
					t_query := t_query || 'NOT_BEFORE ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				ELSIF t_sort = 4 THEN
					t_query := t_query || 'NOT_AFTER ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				ELSE
					t_query := t_query || 'ISSUER_NAME ' || t_orderBy || ', NOT_BEFORE ' || t_orderBy || ', NAME_VALUE';
				END IF;
			ELSE
				-- Group certs for the same identity issued by the same CA.
				t_select := t_select ||
							'        min(__cert_id_field__) ID,' || chr(10) ||
							'        count(DISTINCT __cert_id_field__) NUM_CERTS';
				t_notBefore_field := '';
				t_notAfter_field := '';
				t_serialNumber_field := '';

				t_query :=	'    GROUP BY __issuer_ca_id_table__.ISSUER_CA_ID, ISSUER_NAME' || chr(10) ||
							'    ORDER BY ';
				IF t_sort = 3 THEN
					t_query := t_query || 'ISSUER_NAME ' || t_orderBy || ', NAME_VALUE, NUM_CERTS';
				ELSE
					t_query := t_query || 'NUM_CERTS ' || t_orderBy || ', NAME_VALUE, ISSUER_NAME';
				END IF;
			END IF;

			t_temp := NULL;
			IF t_type = 'CT Entry ID' THEN
				t_needMinEntryTimestamp := FALSE;

				t_from := t_from || 'ct_log_entry ctle,' || chr(10) ||
							'         ct_log ctl';
				t_issuerCAID_table := 'c';
				t_nameValue := 'ctl.NAME';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'ctle.ENTRY_TIMESTAMP';
				t_joinToCertificate_table := 'ctle';
				t_where :=	'ctle.ENTRY_ID = $1::bigint' || chr(10) ||
							'ctle.CT_LOG_ID = ctl.ID';
			ELSIF t_type = 'Serial Number' THEN
				t_from := t_from || 'certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(x509_serialNumber(c.CERTIFICATE), ''hex'')';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=	'x509_serialNumber(c.CERTIFICATE) = decode($1, ''hex'')';
			ELSIF t_type = 'Subject Key Identifier' THEN
				t_from := t_from || 'certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(x509_subjectKeyIdentifier(c.CERTIFICATE), ''hex'')';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=	'x509_subjectKeyIdentifier(c.CERTIFICATE) = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-1(SubjectPublicKeyInfo)' THEN
				t_from := t_from || 'certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_publickey(c.CERTIFICATE), ''sha1''), ''hex'')';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=	'digest(x509_publickey(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-256(SubjectPublicKeyInfo)' THEN
				t_from := t_from || 'certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_publickey(c.CERTIFICATE), ''sha256''), ''hex'')';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=	'digest(x509_publickey(c.CERTIFICATE), ''sha256'') = decode($1, ''hex'')';
			ELSIF t_type = 'SHA-1(Subject)' THEN
				t_from := t_from || 'certificate c';
				t_issuerCAID_table := 'c';
				t_nameValue := 'encode(digest(x509_name(c.CERTIFICATE), ''sha1''), ''hex'')';
				t_certID_field := 'c.ID';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=	'digest(x509_name(c.CERTIFICATE), ''sha1'') = decode($1, ''hex'')';
			ELSIF lower(t_type) LIKE '%lint' THEN
				t_from := t_from || 'lint_issue li,' || chr(10) ||
							'         lint_cert_issue lci';
				t_issuerCAID_table := 'c';
				t_nameValue := 'lci.LINT_ISSUE_ID::text';
				t_certID_field := 'lci.CERTIFICATE_ID';
				t_joinToCertificate_table := 'lci';
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				t_where :=  'lci.LINT_ISSUE_ID = $1::integer' || chr(10) ||
							'lci.NOT_BEFORE_DATE >= $2' || chr(10) ||
							'lci.CERTIFICATE_ID = c.ID' || chr(10) ||
							'lci.LINT_ISSUE_ID = li.ID';
				IF t_linter IS NOT NULL THEN
					t_where := t_where || chr(10) ||
							'li.LINTER = ''' || t_linter || '''';
				END IF;
			ELSE
				t_temp :=	'WITH ci AS (' || chr(10) ||
							'    SELECT min(sub.CERTIFICATE_ID) ID,' || chr(10) ||
							'           min(sub.ISSUER_CA_ID) ISSUER_CA_ID,' || chr(10) ||
							'           array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,' || chr(10) ||
							'           x509_commonName(sub.CERTIFICATE) COMMON_NAME,' || chr(10) ||
							'           x509_notBefore(sub.CERTIFICATE) NOT_BEFORE,' || chr(10) ||
							'           x509_notAfter(sub.CERTIFICATE) NOT_AFTER,' || chr(10) ||
							'           encode(x509_serialNumber(sub.CERTIFICATE), ''hex'') SERIAL_NUMBER' || chr(10) ||
							'        FROM (SELECT *' || chr(10) ||
							'                  FROM certificate_and_identities cai' || chr(10) ||
							'                  WHERE ' || t_tsqueryFunction || '(''certwatch'', $1) @@ identities(cai.CERTIFICATE)' || chr(10);
				IF t_match = 'Single' THEN
					t_temp := t_temp ||
							'                      AND plainto_tsquery(''certwatch'', $1) @@ to_tsvector(''certwatch'', cai.NAME_VALUE)' || chr(10);
				ELSIF t_match = 'FTS' THEN
					t_temp := t_temp ||
							'                      AND to_tsquery(''certwatch'', $1) @@ to_tsvector(''certwatch'', cai.NAME_VALUE)' || chr(10);
				ELSIF t_match != 'Any' THEN
					t_temp := t_temp ||
							'                      AND cai.NAME_VALUE ' || t_match || ' ';
					IF t_match != '=' THEN
						t_temp := t_temp || '(''%'' || ';
					END IF;
					t_temp := t_temp || '$1';
					IF t_match != '=' THEN
						t_temp := t_temp || ' || ''%'')';
					END IF;
					t_temp := t_temp || chr(10);
				END IF;
				IF t_type != 'Identity' THEN
					t_temp := t_temp ||
							'                      AND cai.NAME_TYPE = ' || quote_literal(t_nameType_oid) || ' -- ' || t_nameType || chr(10);
				END IF;
				IF t_excludeExpired IS NOT NULL THEN
					t_temp := t_temp ||
							'                      AND coalesce(x509_notAfter(cai.CERTIFICATE), ''infinity''::timestamp) >= date_trunc(''year'', now() AT TIME ZONE ''UTC'')' || chr(10) ||
							'                      AND x509_notAfter(cai.CERTIFICATE) >= now() AT TIME ZONE ''UTC''' || chr(10);
				END IF;
				IF t_excludeCAsString IS NOT NULL THEN
					t_temp := t_temp ||
							'                      AND cai.ISSUER_CA_ID NOT IN (' || array_to_string(t_excludeCAs, ',') || ')' || chr(10);
				END IF;
				IF t_deduplicate THEN
					t_temp := t_temp ||
							'                      AND NOT EXISTS (' || chr(10) ||
							'                          SELECT 1' || chr(10) ||
							'                              FROM certificate c2' || chr(10) ||
							'                              WHERE x509_serialNumber(c2.CERTIFICATE) = x509_serialNumber(cai.CERTIFICATE)' || chr(10) ||
							'                                  AND c2.ISSUER_CA_ID = cai.ISSUER_CA_ID' || chr(10) ||
							'                                  AND c2.ID < cai.CERTIFICATE_ID' || chr(10) ||
							'                                  AND x509_tbscert_strip_ct_ext(c2.CERTIFICATE) = x509_tbscert_strip_ct_ext(cai.CERTIFICATE)' || chr(10) ||
							'                              LIMIT 1' || chr(10) ||
							'                      )' || chr(10);
				END IF;

				t_select := t_temp ||
							'                  LIMIT 10000' || chr(10) ||
							'             ) sub' || chr(10) ||
							'        GROUP BY sub.CERTIFICATE' || chr(10) ||
							')' || chr(10) ||
							t_select;
				t_entryTimestamp_field := 'le.ENTRY_TIMESTAMP';
				IF (coalesce(t_groupBy, '') = 'none') AND (t_type != 'Common Name') THEN
					t_commonName_field := chr(10) || '        ci.COMMON_NAME,';
				END IF;
				t_notBefore_field := 'ci.NOT_BEFORE';
				t_notAfter_field := 'ci.NOT_AFTER';
				t_serialNumber_field := 'ci.SERIAL_NUMBER';
				t_from := t_from || 'ci';
				t_issuerCAID_table := 'ci';
				t_nameValue := 'array_to_string(ci.NAME_VALUES, chr(10))';
				t_certID_field := 'ci.ID';
			END IF;

			IF t_needMinEntryTimestamp THEN
				t_from := t_from || chr(10) ||
							'            LEFT JOIN LATERAL (' || chr(10) ||
							'                SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP' || chr(10) ||
							'                    FROM ct_log_entry ctle' || chr(10) ||
							'                    WHERE ctle.CERTIFICATE_ID = __cert_id_field__' || chr(10) ||
							'            ) le ON TRUE';
			END IF;

			IF t_joinToCertificate_table IS NOT NULL THEN
				t_from := t_from || ',' || chr(10) ||
							'         certificate c';
				t_where := t_where || chr(10) ||
							t_joinToCertificate_table || '.CERTIFICATE_ID = c.ID';
			END IF;

			t_from := t_from || ',' || chr(10) ||
							'         ca';
			t_where := t_where || chr(10) ||
							t_issuerCAID_table || '.ISSUER_CA_ID = ca.ID';

			IF (t_excludeExpired IS NOT NULL) AND (t_temp IS NULL) THEN
				t_where := t_where || chr(10) ||
							'coalesce(x509_notAfter(c.CERTIFICATE), ''infinity''::timestamp) >= date_trunc(''year'', now() AT TIME ZONE ''UTC'')' || chr(10) ||
							'x509_notAfter(c.CERTIFICATE) >= now() AT TIME ZONE ''UTC''';
			END IF;
			IF (t_excludeCAsString IS NOT NULL) AND (t_temp IS NULL) THEN
				t_where := t_where || chr(10) ||
							t_issuerCAID_table || '.ISSUER_CA_ID NOT IN (' || array_to_string(t_excludeCAs, ',') || ')';
			END IF;

			IF t_where != '' THEN
				t_where := '    WHERE ' || replace(trim(chr(10) from t_where), chr(10), chr(10) || '        AND ') || chr(10);
			END IF;

			IF coalesce(t_groupBy, '') != 'none' THEN
				t_nameValue := '''''';
				t_showIdentity := FALSE;
			ELSE
				t_showIdentity := (t_match NOT IN ('=', 'Any')) OR (t_type = 'CT Entry ID');
			END IF;

			t_query := t_select || chr(10)
					|| t_from || chr(10)
					|| t_where
					|| t_query;

			t_query := replace(t_query, '__issuer_ca_id_table__', t_issuerCAID_table);
			t_query := replace(t_query, '__name_value__', t_nameValue);
			t_query := replace(t_query, '__cert_id_field__', t_certID_field);
			t_query := replace(t_query, '__entry_timestamp_field__', t_entryTimestamp_field);
			t_query := replace(t_query, '__common_name_field__', coalesce(t_commonName_field, ''));
			t_query := replace(t_query, '__not_before_field__', t_notBefore_field);
			t_query := replace(t_query, '__not_after_field__', t_notAfter_field);
			t_query := replace(t_query, '__serial_number_field__', t_serialNumber_field);

			IF t_outputType = 'json' THEN
				t_output := t_output || '[';
			END IF;

			t_text := '';
			t_summary := '';
			t_temp3 := '';
			FOR l_record IN EXECUTE t_query
							USING t_value, t_minNotBefore LOOP
				t_temp2 := '';
				IF t_outputType = 'atom' THEN
					IF coalesce(t_certificateID, -l_record.ID) != l_record.ID THEN
						IF lower(t_type) NOT LIKE '%lint' THEN
							t_text := replace(t_text, '__entry_summary__', t_summary);
						END IF;
						t_summary := l_record.NAME_VALUE;
						t_certificateID := l_record.ID;
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
						WHERE c.ID = l_record.ID;
					t_b64Certificate := replace(encode(t_certificate, 'base64'), chr(10), '');
					t_feedUpdated := greatest(t_feedUpdated, l_record.ENTRY_TIMESTAMP);
					t_temp2 := t_temp2 ||
'  <entry>
    <id>https://crt.sh/?id=' || l_record.ID || '#' || t_cmd || ';' || t_value || '</id>
    <link rel="alternate" type="text/html" href="https://crt.sh/?id=' || l_record.ID || '"/>
    <summary type="html">__entry_summary__&lt;br&gt;&lt;br&gt;&lt;div style="font:8pt monospace"&gt;-----BEGIN CERTIFICATE-----';
					WHILE length(t_b64Certificate) > 0 LOOP
						t_temp2 := t_temp2 || '&lt;br&gt;' || substring(
							t_b64Certificate from 1 for 64
						);
						t_b64Certificate := substring(t_b64Certificate from 65);
					END LOOP;
					t_temp2 := t_temp2 ||
'&lt;br&gt;-----END CERTIFICATE-----&lt;/div&gt;
    </summary>
    <title>[';
					IF x509_print(t_certificate) LIKE '%CT Precertificate Poison%' THEN
						t_temp2 := t_temp2 || 'Precertificate';
					ELSE
						t_temp2 := t_temp2 || 'Certificate';
					END IF;
					t_temp2 := t_temp2 ||
'] Issued by ' || get_ca_name_attribute(l_record.ISSUER_CA_ID)
			|| '; Valid from ' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || ' to '
			|| t_temp || '</title>
    <published>' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</published>
    <updated>' || to_char(l_record.ENTRY_TIMESTAMP, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</updated>
  </entry>
';
				ELSIF t_outputType = 'json' THEN
					t_output := t_output || t_temp3 || row_to_json(l_record, FALSE);
					t_temp3 := ',';
				ELSIF t_outputType = 'html' THEN
					t_temp2 := t_temp2 ||
'  <TR>
    <TD style="text-align:center">';
					IF coalesce(t_groupBy, '') = 'none' THEN
						t_temp2 := t_temp2 || '<A href="?id=' || l_record.ID::text || t_opt || '">' || l_record.ID::text || '</A></TD>
    <TD style="text-align:center;white-space:nowrap">' || coalesce(to_char(l_record.ENTRY_TIMESTAMP, 'YYYY-MM-DD'), '&nbsp;') || '</TD>
    <TD style="text-align:center;white-space:nowrap">' || to_char(l_record.NOT_BEFORE, 'YYYY-MM-DD') || '</TD>
    <TD style="text-align:center;white-space:nowrap">' || to_char(l_record.NOT_AFTER, 'YYYY-MM-DD');
						IF t_commonName_field IS NOT NULL THEN
							t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(html_escape(l_record.COMMON_NAME), '&nbsp;');
						END IF;
					ELSIF (l_record.NUM_CERTS = 1)
							AND (l_record.ID IS NOT NULL) THEN
						t_temp2 := t_temp2 || '<A href="?id=' || l_record.ID::text || t_opt || '">'
															|| l_record.NUM_CERTS::text || '</A>';
					ELSIF (l_record.ISSUER_CA_ID IS NOT NULL)
							AND (l_record.ID IS NOT NULL) THEN
						t_temp2 := t_temp2 || '<A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value)
												|| '&iCAID=' || l_record.ISSUER_CA_ID::text || t_minNotBeforeString
												|| coalesce(t_excludeExpired, '') || t_opt || '">'
											|| l_record.NUM_CERTS::text || '</A>';
					ELSE
						t_temp2 := t_temp2 || l_record.NUM_CERTS::text;
					END IF;
					t_temp2 := t_temp2 || '</TD>
    <TD>';
					IF t_showIdentity THEN
						t_temp2 := t_temp2 || replace(html_escape(l_record.NAME_VALUE), chr(10), '<BR>') || '</TD>
    <TD>';
					END IF;
					IF l_record.ISSUER_CA_ID IS NOT NULL THEN
						t_temp2 := t_temp2 || '<A style="white-space:normal" href="?caid=' || l_record.ISSUER_CA_ID::text || t_opt || '">'
									|| coalesce(html_escape(l_record.ISSUER_NAME), '&nbsp;')
									|| '</A>';
					ELSE
						t_temp2 := t_temp2 || coalesce(html_escape(l_record.ISSUER_NAME), '?');
					END IF;
					IF lower(t_type) LIKE '%lint' THEN
						SELECT cc.INCLUDED_CERTIFICATE_OWNER
							INTO t_temp
							FROM ca_certificate cac, ccadb_certificate cc
							WHERE cac.CA_ID = l_record.ISSUER_CA_ID
								AND cac.CERTIFICATE_ID = cc.CERTIFICATE_ID
							GROUP BY cc.INCLUDED_CERTIFICATE_OWNER
							ORDER BY count(*) DESC
							LIMIT 1;
						t_temp2 := t_temp2 || '</TD>
    <TD>' || coalesce(t_temp, '&nbsp;');
					END IF;
					t_temp2 := t_temp2 || '</TD>
  </TR>
';
				END IF;
				t_text := t_text || t_temp2;
			END LOOP;

			t_temp := replace(
				urlEncode(t_cmd) || '=' || urlEncode(t_value) || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, ''),
				'&', '&amp;'
			);
			IF t_outputType = 'atom' THEN
				t_output :=
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::text || '
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
					t_output := t_output || html_escape(t_cmd) || '=' || html_escape(t_value);
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
  <updated>' || to_char(coalesce(t_feedUpdated, now() AT TIME ZONE 'UTC'), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || '</updated>
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
    <TH style="white-space:nowrap"><A href="?' || t_temp || '&dir=' || t_oppositeDirection || '&sort=4' || t_minNotBeforeString || coalesce(t_excludeExpired, '') || coalesce(t_excludeCAsString, '') || t_groupByParameter || '">Not After</A>
';
						IF t_sort = 4 THEN
							t_output := t_output || ' ' || t_dirSymbol;
						END IF;
						t_output := t_output ||
'    </TH>
';
						IF t_commonName_field IS NOT NULL THEN
							t_output := t_output ||
'    <TH>Common Name</TH>
';
						END IF;
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
'    <TH>Matching Identities</TH>
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
'    <TH>Root Owner (CCADB)</TH>
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
			ELSIF t_outputType = 'json' THEN
				t_output := t_output || ']';
			END IF;
		END IF;

	ELSIF lower(t_type) LIKE '%lint: summary' THEN
		t_cacheControlMaxAge := -1;

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

		IF t_groupBy NOT IN ('', 'IssuerO') THEN
			t_output := t_output ||
'  <BR><BR>Sorry, "IssuerO" is the only currently supported value for "group".
';
		ELSE
			IF t_outputType = 'html' THEN
				t_output := t_output ||
'  <SPAN style="position:absolute">
    &nbsp; &nbsp; &nbsp; <A style="font-size:8pt;vertical-align:sub" href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_direction || '&sort=' || t_sort::text || t_issuerOParameter;
				IF t_groupBy != 'IssuerO' THEN
					t_output := t_output || '&group=IssuerO">Group';
				ELSE
					t_output := t_output || '">Ungroup';
				END IF;
				t_output := t_output || ' by "Issuer O"</A>
';
				IF t_issuerO IS NOT NULL THEN
					t_output := t_output || ' &nbsp; &nbsp; <A style="font-size:8pt;vertical-align:sub" href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value)
										|| '&dir=' || t_direction || '&sort=' || t_sort::text || t_groupByParameter || '">Show all "Issuer O"s</A>
';
				END IF;
				t_output := t_output ||
'  </SPAN>
  <BR><BR>
  For certificates with <B>notBefore >= ' || to_char((now() AT TIME ZONE 'UTC')::date - t_value::interval, 'YYYY-MM-DD') || '</B>';
				IF t_issuerO IS NOT NULL THEN
					t_output := t_output || ' and <B>"Issuer O" LIKE ''' || t_issuerO || '''</B>';
				END IF;
				t_output := t_output || ':
  <BR><BR>
  <TABLE class="lint">
    <TR>
      <TH rowspan="2"><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=1' || t_groupByParameter || t_issuerOParameter || '">Issuer O</A>';
				IF t_sort = 1 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				IF t_groupBy != 'IssuerO' THEN
					t_output := t_output || '</TH>
      <TH rowspan="2"><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=2' || t_groupByParameter || t_issuerOParameter || '">Issuer CN, OU or O</A>';
					IF t_sort = 2 THEN
						t_output := t_output || ' ' || t_dirSymbol;
					END IF;
				END IF;
				t_output := t_output || '</TH>
      <TH rowspan="2"><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=3' || t_groupByParameter || t_issuerOParameter || '"># Certs</A>';
				IF t_sort = 3 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH colspan="4">Issues Found</TH>
    </TR>
    <TR>
      <TH><A title="These errors are fatal to the checks and prevent most further checks from being executed.  These are extremely bad errors." href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=4' || t_groupByParameter || t_issuerOParameter || '">#</A> <SPAN class="fatal">&nbsp;FATAL&nbsp;</SPAN>';
				IF t_sort = 4 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A title="These are issues where the certificate is not compliant with the standard." href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=7' || t_groupByParameter || t_issuerOParameter || '">#</A> <SPAN class="error">&nbsp;ERROR&nbsp;</SPAN>';
				IF t_sort = 7 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A title="These are issues where a standard recommends differently but the standard uses terms such as ''SHOULD'' or ''MAY''." href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=10' || t_groupByParameter || t_issuerOParameter || '">#</A> <SPAN class="warning">&nbsp;WARNING&nbsp;</SPAN>';
				IF t_sort = 10 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
      <TH><A title="FATAL + ERROR + WARNING" href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=16' || t_groupByParameter || t_issuerOParameter || '">#</A> ALL';
				IF t_sort = 16 THEN
					t_output := t_output || ' ' || t_dirSymbol;
				END IF;
				t_output := t_output || '</TH>
    </TR>
';
			ELSIF t_outputType = 'json' THEN
				t_output := t_output || '[';
			END IF;

			t_query := 	'WITH certs AS (' || chr(10) ||
						'  SELECT ls.ISSUER_CA_ID, sum(ls.NO_OF_CERTS) AS CERTS_LINTED' || chr(10) ||
						'    FROM lint_summary ls' || chr(10) ||
						'    WHERE ls.NOT_BEFORE_DATE >= (now() AT TIME ZONE ''UTC'')::date - interval ''1 week''' || chr(10) ||
						'      AND ls.LINT_ISSUE_ID = -1' || chr(10) ||
						'    GROUP BY ls.ISSUER_CA_ID' || chr(10) ||
						'), issues AS (' || chr(10) ||
						'  SELECT ls.ISSUER_CA_ID,' || chr(10) ||
						'         sum(CASE WHEN li.SEVERITY=''W'' THEN ls.NO_OF_CERTS ELSE 0 END) WARNING_ISSUES,' || chr(10) ||
						'         sum(CASE WHEN li.SEVERITY=''E'' THEN ls.NO_OF_CERTS ELSE 0 END) ERROR_ISSUES,' || chr(10) ||
						'         sum(CASE WHEN li.SEVERITY=''F'' THEN ls.NO_OF_CERTS ELSE 0 END) FATAL_ISSUES' || chr(10) ||
						'    FROM lint_summary ls, lint_issue li' || chr(10) ||
						'    WHERE ls.NOT_BEFORE_DATE >= (now() AT TIME ZONE ''UTC'')::date - interval ''1 week''' || chr(10) ||
						'      AND ls.LINT_ISSUE_ID != -1' || chr(10) ||
						'      AND ls.LINT_ISSUE_ID = li.ID' || chr(10);
			IF t_linter IS NOT NULL THEN
				t_query := t_query ||
						'      AND li.LINTER = ''' || t_linter || '''' || chr(10);
			END IF;
			t_query := t_query ||
						'    GROUP BY ls.ISSUER_CA_ID' || chr(10) ||
						')' || chr(10);

			IF t_groupBy = 'IssuerO' THEN
				t_query := t_query ||
						'SELECT sum(certs.CERTS_LINTED)::bigint CERTS_LINTED,' || chr(10) ||
						'       sum(coalesce(issues.WARNING_ISSUES, 0))::bigint WARNING_ISSUES,' || chr(10) ||
						'       sum(coalesce(issues.ERROR_ISSUES, 0))::bigint ERROR_ISSUES,' || chr(10) ||
						'       sum(coalesce(issues.FATAL_ISSUES, 0))::bigint FATAL_ISSUES,' || chr(10) ||
						'       sum(coalesce(issues.WARNING_ISSUES::bigint + issues.ERROR_ISSUES + issues.FATAL_ISSUES, 0))::bigint ALL_ISSUES,' || chr(10) ||
						'       get_ca_name_attribute(certs.ISSUER_CA_ID, ''organizationName'') ISSUER_ORGANIZATION_NAME,' || chr(10) ||
						'       NULL::text ISSUER_FRIENDLY_NAME' || chr(10) ||
						'  FROM certs' || chr(10) ||
						'         LEFT OUTER JOIN issues ON (' || chr(10) ||
						'           certs.ISSUER_CA_ID = issues.ISSUER_CA_ID' || chr(10) ||
						'         )' || chr(10) ||
						'  GROUP BY ISSUER_ORGANIZATION_NAME' || chr(10);
				IF t_sort = 1 THEN
					t_query := t_query ||
							'  ORDER BY ISSUER_ORGANIZATION_NAME ' || t_orderBy;
				ELSIF t_sort = 3 THEN
					t_query := t_query ||
							'  ORDER BY CERTS_LINTED ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				ELSIF t_sort = 4 THEN
					t_query := t_query ||
							'  ORDER BY FATAL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				ELSIF t_sort = 7 THEN
					t_query := t_query ||
							'  ORDER BY ERROR_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				ELSIF t_sort = 10 THEN
					t_query := t_query ||
							'  ORDER BY WARNING_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				ELSIF t_sort = 16 THEN
					t_query := t_query ||
							'  ORDER BY ALL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				END IF;
			ELSE
				t_query := t_query ||
						'SELECT certs.ISSUER_CA_ID,' || chr(10) ||
						'       certs.CERTS_LINTED,' || chr(10) ||
						'       coalesce(issues.WARNING_ISSUES, 0) WARNING_ISSUES,' || chr(10) ||
						'       coalesce(issues.ERROR_ISSUES, 0) ERROR_ISSUES,' || chr(10) ||
						'       coalesce(issues.FATAL_ISSUES, 0) FATAL_ISSUES,' || chr(10) ||
						'       coalesce(issues.WARNING_ISSUES::bigint + issues.ERROR_ISSUES + issues.FATAL_ISSUES, 0) ALL_ISSUES,' || chr(10) ||
						'       get_ca_name_attribute(certs.ISSUER_CA_ID, ''organizationName'') ISSUER_ORGANIZATION_NAME,' || chr(10) ||
						'       get_ca_name_attribute(certs.ISSUER_CA_ID, ''_friendlyName_'') ISSUER_FRIENDLY_NAME' || chr(10) ||
						'  FROM certs' || chr(10) ||
						'         LEFT OUTER JOIN issues ON (' || chr(10) ||
						'           certs.ISSUER_CA_ID = issues.ISSUER_CA_ID' || chr(10) ||
						'         )' || chr(10);
				IF t_sort = 1 THEN
					t_query := t_query ||
							'  ORDER BY ISSUER_ORGANIZATION_NAME ' || t_orderBy || ', ISSUER_FRIENDLY_NAME';
				ELSIF t_sort = 2 THEN
					t_query := t_query ||
							'  ORDER BY ISSUER_FRIENDLY_NAME ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME';
				ELSIF t_sort = 3 THEN
					t_query := t_query ||
							'  ORDER BY CERTS_LINTED ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
				ELSIF t_sort = 4 THEN
					t_query := t_query ||
							'  ORDER BY FATAL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
				ELSIF t_sort = 7 THEN
					t_query := t_query ||
							'  ORDER BY ERROR_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
				ELSIF t_sort = 10 THEN
					t_query := t_query ||
							'  ORDER BY WARNING_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
				ELSIF t_sort = 16 THEN
					t_query := t_query ||
							'  ORDER BY ALL_ISSUES ' || t_orderBy || ', ISSUER_ORGANIZATION_NAME, ISSUER_FRIENDLY_NAME';
				END IF;
			END IF;

			t_temp3 := '';
			FOR l_record IN EXECUTE t_query USING t_issuerO LOOP
				IF t_outputType = 'json' THEN
					t_output := t_output || t_temp3 || row_to_json(l_record, FALSE);
					t_temp3 := ',';
				ELSIF t_outputType = 'html' THEN
					t_output := t_output || '
    <TR>
      <TD>';
					IF l_record.ISSUER_ORGANIZATION_NAME IS NOT NULL THEN
						t_output := t_output || '<A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_direction
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
'      <TD>' || l_record.CERTS_LINTED::text || '</TD>
      <TD>' || l_record.FATAL_ISSUES::text || '</TD>
      <TD>' || l_record.ERROR_ISSUES::text || '</TD>
      <TD>' || l_record.WARNING_ISSUES::text || '</TD>
      <TD>' || l_record.ALL_ISSUES::text || '</TD>
    </TR>
';
				END IF;
			END LOOP;

			IF t_outputType = 'html' THEN
				t_output := t_output ||
'  </TABLE>
';
			ELSIF t_outputType = 'json' THEN
				t_output := t_output || ']';
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
      <TH><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=1' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '">Severity</A>';
			IF t_sort = 1 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
      <TH><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=2' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '">Issue</A>';
			IF t_sort = 2 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
      <TH><A href="?' || urlEncode(t_cmd) || '=' || urlEncode(t_value) || '&dir=' || t_oppositeDirection || '&sort=3' || t_groupByParameter || coalesce(t_excludeAffectedCerts, '') || '"># Affected Certs</A>';
			IF t_sort = 3 THEN
				t_output := t_output || ' ' || t_dirSymbol;
			END IF;
			t_output := t_output || '</TH>
    </TR>
';
		ELSIF t_outputType = 'json' THEN
			t_output := t_output || '[';
		END IF;

		t_query :=	'SELECT li.ID, li.ISSUE_TEXT,';
		IF t_excludeAffectedCerts IS NULL THEN
			t_query := t_query || ' sum(ls.NO_OF_CERTS) NUM_CERTS,';
		ELSE
			t_query := t_query || ' -1::bigint NUM_CERTS,';
		END IF;
		t_query := t_query || chr(10) ||
					'       CASE li.SEVERITY' || chr(10) ||
					'         WHEN ''F'' THEN 1' || chr(10) ||
					'         WHEN ''E'' THEN 2' || chr(10) ||
					'         WHEN ''W'' THEN 3' || chr(10) ||
					'         ELSE 4' || chr(10) ||
					'       END ISSUE_TYPE,' || chr(10) ||
					'       CASE li.SEVERITY' || chr(10) ||
					'         WHEN ''F'' THEN ''FATAL''' || chr(10) ||
					'         WHEN ''E'' THEN ''ERROR''' || chr(10) ||
					'         WHEN ''W'' THEN ''WARNING''' || chr(10) ||
					'         ELSE li.SEVERITY ' || chr(10) ||
					'       END ISSUE_HEADING,' || chr(10) ||
					'       CASE li.SEVERITY' || chr(10) ||
					'         WHEN ''F'' THEN ''class="fatal"''' || chr(10) ||
					'         WHEN ''E'' THEN ''class="error"''' || chr(10) ||
					'         WHEN ''W'' THEN ''class="warning"''' || chr(10) ||
					'         ELSE ''''' || chr(10) ||
					'       END ISSUE_CLASS' || chr(10);
		IF t_excludeAffectedCerts IS NULL THEN
			t_query := t_query ||
					'    FROM lint_summary ls, lint_issue li, ca' || chr(10) ||
					'    WHERE ls.LINT_ISSUE_ID = li.ID' || chr(10) ||
					'        AND ls.ISSUER_CA_ID = ca.ID' || chr(10) ||
					'        AND ca.LINTING_APPLIES' || chr(10);
			IF t_linter IS NOT NULL THEN
				t_query := t_query ||
					'        AND li.LINTER = ''' || t_linter || '''' || chr(10);
			END IF;
			t_query := t_query ||
					'        AND ls.NOT_BEFORE_DATE >= $1' || chr(10) ||
					'    GROUP BY li.ID, li.SEVERITY, li.ISSUE_TEXT' || chr(10);
		ELSE
			t_query := t_query ||
					'    FROM lint_issue li' || chr(10);
			IF t_linter IS NOT NULL THEN
				t_query := t_query ||
					'    WHERE li.LINTER = ''' || t_linter || '''' || chr(10);
			END IF;
		END IF;
		IF t_sort = 1 THEN
			t_query := t_query ||
					'    ORDER BY ISSUE_TYPE, li.ISSUE_TEXT ' || t_orderBy;
		ELSIF t_sort = 2 THEN
			t_query := t_query ||
					'    ORDER BY li.ISSUE_TEXT ' || t_orderBy;
		ELSIF t_sort = 3 THEN
			t_query := t_query ||
					'    ORDER BY NUM_CERTS ' || t_orderBy;
		END IF;

		t_temp3 := '';
		FOR l_record IN EXECUTE t_query USING t_minNotBefore LOOP
			IF t_outputType = 'json' THEN
				t_output := t_output || t_temp3 || row_to_json(l_record, FALSE);
				t_temp3 := ',';
			ELSIF t_outputType = 'html' THEN
				t_output := t_output ||
'    <TR>
      <TD ' || l_record.ISSUE_CLASS || '>' || l_record.ISSUE_HEADING || '</TD>
      <TD ' || l_record.ISSUE_CLASS || '>' || l_record.ISSUE_TEXT || '</TD>
      <TD><A href="?' || urlEncode(t_cmd) || '=' || l_record.ID::text || t_minNotBeforeString || '">';
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
		ELSIF t_outputType = 'json' THEN
			t_output := t_output || ']';
		END IF;

	ELSE
		t_output := t_output || ' <SPAN class="whiteongrey">Error</SPAN>
<BR><BR>''' || name || ''' is an unsupported action!
';

	END IF;

	IF t_outputType = 'html' THEN
		IF t_cacheControlMaxAge = -1 THEN
			t_temp := 'no-cache';
		ELSE
			t_temp := 'max-age=' || t_cacheControlMaxAge::text;
		END IF;
		t_output :=
'[BEGIN_HEADERS]
Cache-Control: ' || t_temp || '
Content-Type: text/html; charset=UTF-8
[END_HEADERS]
' || t_output || '
  <BR><BR><BR>
';
		IF t_showSQL AND (t_query IS NOT NULL) THEN
			t_output := t_output || '<BR><BR><TEXTAREA cols="160" rows="30">' || t_query || ';</TEXTAREA>';
		END IF;
		t_output := t_output || '
  <P class="copyright">&copy; Sectigo Limited 2015-2023. All rights reserved.</P>
  <DIV>
    <A href="https://sectigo.com/"><IMG src="/sectigo_s.png"></A>
    &nbsp;<A href="https://github.com/crtsh"><IMG src="/GitHub-Mark-32px.png"></A>
  </DIV>
</BODY>
</HTML>';
	END IF;

	IF t_cacheResponse THEN
		INSERT INTO cached_response (
				PAGE_NAME, GENERATED_AT, RESPONSE_BODY
			)
			VALUES (
				t_type, now() AT TIME ZONE 'UTC', t_output
			)
			ON CONFLICT (PAGE_NAME) DO UPDATE
				SET GENERATED_AT = now() AT TIME ZONE 'UTC',
					RESPONSE_BODY = t_output;
		RETURN 'Cached';
	ELSE
		RETURN t_output;
	END IF;

EXCEPTION
	WHEN no_data_found THEN
		RETURN
'[BEGIN_HEADERS]
Cache-Control: max-age=' || t_cacheControlMaxAge::text || '
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
Cache-Control: max-age=' || t_cacheControlMaxAge::text || '
Content-Type: text/html; charset=UTF-8
[END_HEADERS]
' || coalesce(t_output, '') || '<BR><BR>' || html_escape(SQLERRM) || '<BR><BR>' || html_escape(coalesce(t_temp, '')) || '<BR><BR>' || html_escape(coalesce(t_query, ''));
END;
$$ LANGUAGE plpgsql;
