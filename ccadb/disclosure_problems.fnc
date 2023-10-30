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

CREATE OR REPLACE FUNCTION disclosure_problems(
	certificateID		ccadb_certificate.CERTIFICATE_ID%TYPE,
	trustContextID		trust_context.ID%TYPE
) RETURNS text[]
AS $$
DECLARE
	t_ccadbCertificate		ccadb_certificate%ROWTYPE;
	t_disclosureStatus		disclosure_status_type;
	t_crlDisclosureRequired	boolean		:= FALSE;
	l_crl					RECORD;
	t_notAfter				timestamp;
	t_caID					ca.ID%TYPE;
	t_count					bigint;
	t_problems				text[];
	t_errorMessage			text;
	t_caOwner1				text;
	t_caOwner2				text;
	t_url1					text;
	t_url2					text;
	t_type1					text;
	t_type2					text;
	t_date1					text;
	t_date2					text;
	t_start1				text;
	t_start2				text;
	t_end1					text;
	t_end2					text;
BEGIN
	SELECT cc.*
		INTO t_ccadbCertificate
		FROM ccadb_certificate cc
		WHERE cc.CERTIFICATE_ID = certificateID
		ORDER BY cc.CERT_RECORD_TYPE;	-- 'Intermediate Certificate' ahead of 'Root Certificate'.

	IF trustContextID = 5 THEN
		t_disclosureStatus := t_ccadbCertificate.MOZILLA_DISCLOSURE_STATUS;
	ELSIF trustContextID = 1 THEN
		t_disclosureStatus := t_ccadbCertificate.MICROSOFT_DISCLOSURE_STATUS;
	ELSIF trustContextID = 12 THEN
		t_disclosureStatus := t_ccadbCertificate.APPLE_DISCLOSURE_STATUS;
	ELSIF trustContextID = 6 THEN
		t_disclosureStatus := t_ccadbCertificate.CHROME_DISCLOSURE_STATUS;
	ELSE
		RETURN NULL;
	END IF;

	IF t_disclosureStatus = 'DisclosureIncomplete' THEN
		IF coalesce(t_ccadbCertificate.CP_URL, t_ccadbCertificate.CPS_URL) IS NULL THEN
			t_problems := array_append(t_problems, '"Certificate Policy (CP)" and/or "Certification Practice Statement (CPS)" is required');
		END IF;
		IF coalesce(t_ccadbCertificate.CP_CPS_LAST_UPDATED, now() AT TIME ZONE 'UTC') < (now() AT TIME ZONE 'UTC' - interval '365 days') THEN
			t_problems := array_append(t_problems, '"CP/CPS Last Updated Date" is older than 365 days');
		END IF;
		IF t_ccadbCertificate.STANDARD_AUDIT_URL IS NULL THEN
			t_problems := array_append(t_problems, '"Standard Audit" URL is required');
		END IF;
		IF t_ccadbCertificate.STANDARD_AUDIT_TYPE IS NULL THEN
			t_problems := array_append(t_problems, '"Standard Audit Type" is required');
		END IF;
		IF t_ccadbCertificate.STANDARD_AUDIT_DATE IS NULL THEN
			t_problems := array_append(t_problems, '"Standard Audit Statement Date" is required');
		END IF;
		IF t_ccadbCertificate.STANDARD_AUDIT_START IS NULL THEN
			t_problems := array_append(t_problems, '"Standard Audit Period Start Date" is required');
		END IF;
		IF t_ccadbCertificate.STANDARD_AUDIT_END IS NULL THEN
			t_problems := array_append(t_problems, '"Standard Audit Period End Date" is required');
		END IF;
		IF trustContextID = 12 THEN
			t_crlDisclosureRequired := TRUE;
		END IF;

		PERFORM
			FROM certificate c, ca_trust_purpose ctp
			WHERE c.ID = t_ccadbCertificate.CERTIFICATE_ID
				AND c.ISSUER_CA_ID = ctp.CA_ID
				AND ctp.TRUST_CONTEXT_ID = trustContextID
				AND ctp.TRUST_PURPOSE_ID = 1
				AND (
					x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
					OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
					OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
				)
				AND NOT (
					(ctp.TRUST_CONTEXT_ID = 1)
					AND ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
				)
				AND NOT (
					(ctp.TRUST_CONTEXT_ID = 5)
					AND ctp.ALL_CHAINS_REVOKED_VIA_ONECRL
				);
		IF FOUND THEN
			IF t_ccadbCertificate.BRSSL_AUDIT_URL IS NULL THEN
				t_problems := array_append(t_problems, '"BR Audit" URL is required');
			END IF;
			IF t_ccadbCertificate.BRSSL_AUDIT_TYPE IS NULL THEN
				t_problems := array_append(t_problems, '"BR Audit Type" is required');
			END IF;
			IF t_ccadbCertificate.BRSSL_AUDIT_DATE IS NULL THEN
				t_problems := array_append(t_problems, '"BR Audit Statement Date" is required');
			END IF;
			IF t_ccadbCertificate.BRSSL_AUDIT_START IS NULL THEN
				t_problems := array_append(t_problems, '"BR Audit Period Start Date" is required');
			END IF;
			IF t_ccadbCertificate.BRSSL_AUDIT_END IS NULL THEN
				t_problems := array_append(t_problems, '"BR Audit Period End Date" is required');
			END IF;
			IF trustContextID = 5 THEN
				t_crlDisclosureRequired := TRUE;
			END IF;
		END IF;

		IF t_crlDisclosureRequired THEN
			IF (nullif(t_ccadbCertificate.FULL_CRL_URL, '') IS NULL) AND (nullif(nullif(t_ccadbCertificate.JSON_ARRAY_OF_CRL_URLS, ''), '[""]') IS NULL) THEN
				SELECT ca.ID, coalesce(ca.NUM_ISSUED[1], 0) + coalesce(ca.NUM_ISSUED[2], 0)
					INTO t_caID, t_count
					FROM ca_certificate cac, ca
					WHERE cac.CERTIFICATE_ID = certificateID
						AND cac.CA_ID = ca.ID;
				IF t_count = 0 THEN
					t_problems := array_append(t_problems, '"Full CRL Issued By This CA" or "JSON Array of Partitioned CRLs" may be required (<A href="/?ca=' || t_caID || '" target="_blank">no issuance observed</A>)');
				ELSE
					t_problems := array_append(t_problems, '"Full CRL Issued By This CA" or "JSON Array of Partitioned CRLs" is required (<A href="/?ca=' || t_caID || '" target="_blank">' || t_count::text || ' (pre)cert(s) observed</A>)');
				END IF;
			END IF;
			IF t_ccadbCertificate.FULL_CRL_URL = 'revoked' THEN
				IF t_ccadbCertificate.REVOCATION_STATUS NOT IN ('Revoked', 'Parent Cert Revoked') THEN
					t_problems := array_append(t_problems, '"Full CRL Issued By This CA" indicates "revoked", but this certificate has not been disclosed as "Revoked" or "Parent Cert Revoked"');
				END IF;
			ELSIF t_ccadbCertificate.FULL_CRL_URL = 'expired' THEN
				PERFORM
					FROM certificate c
					WHERE c.ID = certificateID
						AND x509_notAfter(c.CERTIFICATE) > now() AT TIME ZONE 'UTC';
				IF FOUND THEN
					t_problems := array_append(t_problems, '"Full CRL Issued By This CA" indicates "expired", but this certificate has not yet expired');
				END IF;
			ELSIF nullif(t_ccadbCertificate.FULL_CRL_URL, '') IS NOT NULL THEN
				SELECT coalesce(crl.ERROR_MESSAGE, 'EXPIRED (nextUpdate = ' || TO_CHAR(crl.NEXT_UPDATE, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || ')')
					INTO t_errorMessage
					FROM ca_certificate cac, crl
					WHERE cac.CERTIFICATE_ID = t_ccadbCertificate.CERTIFICATE_ID
						AND cac.CA_ID = crl.CA_ID
						AND crl.DISTRIBUTION_POINT_URL = t_ccadbCertificate.FULL_CRL_URL
						AND (
							(crl.ERROR_MESSAGE IS NOT NULL)
							OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
						)
					LIMIT 1;
				IF FOUND THEN
					t_problems := array_append(t_problems, '"Full CRL Issued By This CA" ERROR: ' || t_ccadbCertificate.FULL_CRL_URL || ' => ' || t_errorMessage);
				END IF;
			END IF;
			IF nullif(nullif(t_ccadbCertificate.JSON_ARRAY_OF_CRL_URLS, ''), '[""]') IS NOT NULL THEN
				FOR l_crl IN (
					SELECT coalesce(crl.ERROR_MESSAGE, 'EXPIRED (nextUpdate = ' || TO_CHAR(crl.NEXT_UPDATE, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || ')') ERROR_MESSAGE, json_crl_url
						FROM ca_certificate cac, crl, json_array_elements_text(t_ccadbCertificate.JSON_ARRAY_OF_CRL_URLS::json) json_crl_url
						WHERE cac.CERTIFICATE_ID = t_ccadbCertificate.CERTIFICATE_ID
							AND cac.CA_ID = crl.CA_ID
							AND length(t_ccadbCertificate.JSON_ARRAY_OF_CRL_URLS) > 4	-- Longer than [""].
							AND crl.DISTRIBUTION_POINT_URL = json_crl_url
							AND (
								(crl.ERROR_MESSAGE IS NOT NULL)
								OR (crl.NEXT_UPDATE < now() AT TIME ZONE 'UTC')
							)
				) LOOP
					t_problems := array_append(t_problems, '"JSON Array of Partitioned CRLs" ERROR: ' || l_crl.json_crl_url || ' => ' || l_crl.ERROR_MESSAGE);
				END LOOP;
			END IF;
		END IF;

		PERFORM
			FROM certificate c, ca_trust_purpose ctp, trust_purpose tp
			WHERE c.ID = t_ccadbCertificate.CERTIFICATE_ID
				AND c.ISSUER_CA_ID = ctp.CA_ID
				AND ctp.TRUST_CONTEXT_ID = trustContextID
				AND ctp.TRUST_PURPOSE_ID >= 100
				AND ctp.TRUST_PURPOSE_ID = tp.ID
				AND x509_isPolicyPermitted(c.CERTIFICATE, tp.PURPOSE_OID)
				AND (
					x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.5.5.7.3.1')
					OR x509_isEKUPermitted(c.CERTIFICATE, '1.3.6.1.4.1.311.10.3.3')	-- MS SGC.
					OR x509_isEKUPermitted(c.CERTIFICATE, '2.16.840.1.113730.4.1')	-- NS Step-Up.
				)
				AND NOT (
					(ctp.TRUST_CONTEXT_ID = 1)
					AND ctp.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
				)
				AND NOT (
					(ctp.TRUST_CONTEXT_ID = 5)
					AND ctp.ALL_CHAINS_REVOKED_VIA_ONECRL
				);
		IF FOUND THEN
			IF t_ccadbCertificate.EVSSL_AUDIT_URL IS NULL THEN
				t_problems := array_append(t_problems, '"EV Audit" URL is required');
			END IF;
			IF t_ccadbCertificate.EVSSL_AUDIT_TYPE IS NULL THEN
				t_problems := array_append(t_problems, '"EV Audit Type" is required');
			END IF;
			IF t_ccadbCertificate.EVSSL_AUDIT_DATE IS NULL THEN
				t_problems := array_append(t_problems, '"EV Audit Statement Date" is required');
			END IF;
			IF t_ccadbCertificate.EVSSL_AUDIT_START IS NULL THEN
				t_problems := array_append(t_problems, '"EV Audit Period Start Date" is required');
			END IF;
			IF t_ccadbCertificate.EVSSL_AUDIT_END IS NULL THEN
				t_problems := array_append(t_problems, '"EV Audit Period End Date" is required');
			END IF;
		END IF;

	ELSIF t_disclosureStatus = 'DisclosedWithInconsistentAudit' THEN
		SELECT min(coalesce(nullif(cc2.SUBORDINATE_CA_OWNER, ''), cc2.CA_OWNER)), max(coalesce(nullif(cc2.SUBORDINATE_CA_OWNER, ''), cc2.CA_OWNER)),
				min(coalesce(cc2.STANDARD_AUDIT_URL, '&lt;omitted&gt;')), max(coalesce(cc2.STANDARD_AUDIT_URL, '&lt;omitted&gt;')),
				min(coalesce(cc2.STANDARD_AUDIT_TYPE, '&lt;omitted&gt;')), max(coalesce(cc2.STANDARD_AUDIT_TYPE, '&lt;omitted&gt;')),
				min(coalesce(cc2.STANDARD_AUDIT_DATE::text, '&lt;omitted&gt;')), max(coalesce(cc2.STANDARD_AUDIT_DATE::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.STANDARD_AUDIT_START::text, '&lt;omitted&gt;')), max(coalesce(cc2.STANDARD_AUDIT_START::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.STANDARD_AUDIT_END::text, '&lt;omitted&gt;')), max(coalesce(cc2.STANDARD_AUDIT_END::text, '&lt;omitted&gt;'))
			INTO t_caOwner1, t_caOwner2,
				t_url1, t_url2,
				t_type1, t_type2,
				t_date1, t_date2,
				t_start1, t_start2,
				t_end1, t_end2
			FROM ca_certificate cac, ca_certificate cac2, ccadb_certificate cc2
			WHERE cac.CERTIFICATE_ID = certificateID
				AND cac.CA_ID = cac2.CA_ID
				AND EXISTS (
					SELECT 1
						FROM certificate c, ca_trust_purpose ctp
						WHERE c.ID = cac2.CERTIFICATE_ID
							AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > statement_timestamp() AT TIME ZONE 'UTC'
							AND c.ISSUER_CA_ID = ctp.CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
							AND ctp.IS_TIME_VALID
				)
				AND cac2.CERTIFICATE_ID = cc2.CERTIFICATE_ID
				AND cc2.CCADB_RECORD_ID IS NOT NULL;	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
		IF t_caOwner1 != t_caOwner2 THEN
			t_problems := array_append(t_problems, '"(Subordinate) CA Owner"s: "' || replace(html_escape(t_caOwner1), ' ', '&nbsp;') || '" != "' || replace(html_escape(t_caOwner2), ' ', '&nbsp;') || '"');
		END IF;
		IF t_url1 != t_url2 THEN
			t_problems := array_append(t_problems, '"Standard Audit" URLs: ' || t_url1 || ' != ' || t_url2);
		END IF;
		IF t_type1 != t_type2 THEN
			t_problems := array_append(t_problems, '"Standard Audit Type"s: ' || t_type1 || ' != ' || t_type2);
		END IF;
		IF t_date1 != t_date2 THEN
			t_problems := array_append(t_problems, '"Standard Audit Statement Date"s: ' || t_date1 || ' != ' || t_date2);
		END IF;
		IF t_start1 != t_start2 THEN
			t_problems := array_append(t_problems, '"Standard Audit Period Start Date"s: ' || t_start1 || ' != ' || t_start2);
		END IF;
		IF t_end1 != t_end2 THEN
			t_problems := array_append(t_problems, '"Standard Audit Period End Date"s: ' || t_end1 || ' != ' || t_end2);
		END IF;

		SELECT min(coalesce(cc2.BRSSL_AUDIT_URL, '&lt;omitted&gt;')), max(coalesce(cc2.BRSSL_AUDIT_URL, '&lt;omitted&gt;')),
				min(coalesce(cc2.BRSSL_AUDIT_TYPE, '&lt;omitted&gt;')), max(coalesce(cc2.BRSSL_AUDIT_TYPE, '&lt;omitted&gt;')),
				min(coalesce(cc2.BRSSL_AUDIT_DATE::text, '&lt;omitted&gt;')), max(coalesce(cc2.BRSSL_AUDIT_DATE::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.BRSSL_AUDIT_START::text, '&lt;omitted&gt;')), max(coalesce(cc2.BRSSL_AUDIT_START::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.BRSSL_AUDIT_END::text, '&lt;omitted&gt;')), max(coalesce(cc2.BRSSL_AUDIT_END::text, '&lt;omitted&gt;'))
			INTO t_url1, t_url2,
				t_type1, t_type2,
				t_date1, t_date2,
				t_start1, t_start2,
				t_end1, t_end2
			FROM ca_certificate cac, ca_certificate cac2, ccadb_certificate cc2
			WHERE cac.CERTIFICATE_ID = certificateID
				AND cac.CA_ID = cac2.CA_ID
				AND EXISTS (
					SELECT 1
						FROM certificate c, ca_trust_purpose ctp
						WHERE c.ID = cac2.CERTIFICATE_ID
							AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > statement_timestamp() AT TIME ZONE 'UTC'
							AND c.ISSUER_CA_ID = ctp.CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND ctp.TRUST_PURPOSE_ID = 1
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
							AND ctp.IS_TIME_VALID
				)
				AND cac2.CERTIFICATE_ID = cc2.CERTIFICATE_ID
				AND cc2.CCADB_RECORD_ID IS NOT NULL;	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
		IF FOUND THEN
			IF t_url1 != t_url2 THEN
				t_problems := array_append(t_problems, '"BR Audit" URLs: ' || t_url1 || ' != ' || t_url2);
			END IF;
			IF t_type1 != t_type2 THEN
				t_problems := array_append(t_problems, '"BR Audit Type"s inconsistent: ' || t_type1 || ' != ' || t_type2);
			END IF;
			IF t_date1 != t_date2 THEN
				t_problems := array_append(t_problems, '"BR Audit Statement Date"s: ' || t_date1 || ' != ' || t_date2);
			END IF;
			IF t_start1 != t_start2 THEN
				t_problems := array_append(t_problems, '"BR Audit Period Start Date"s: ' || t_start1 || ' != ' || t_start2);
			END IF;
			IF t_end1 != t_end2 THEN
				t_problems := array_append(t_problems, '"BR Audit Period End Date"s: ' || t_end1 || ' != ' || t_end2);
			END IF;
		END IF;

		SELECT min(coalesce(cc2.EVSSL_AUDIT_URL, '&lt;omitted&gt;')), max(coalesce(cc2.EVSSL_AUDIT_URL, '&lt;omitted&gt;')),
				min(coalesce(cc2.EVSSL_AUDIT_TYPE, '&lt;omitted&gt;')), max(coalesce(cc2.EVSSL_AUDIT_TYPE, '&lt;omitted&gt;')),
				min(coalesce(cc2.EVSSL_AUDIT_DATE::text, '&lt;omitted&gt;')), max(coalesce(cc2.EVSSL_AUDIT_DATE::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.EVSSL_AUDIT_START::text, '&lt;omitted&gt;')), max(coalesce(cc2.EVSSL_AUDIT_START::text, '&lt;omitted&gt;')),
				min(coalesce(cc2.EVSSL_AUDIT_END::text, '&lt;omitted&gt;')), max(coalesce(cc2.EVSSL_AUDIT_END::text, '&lt;omitted&gt;'))
			INTO t_url1, t_url2,
				t_type1, t_type2,
				t_date1, t_date2,
				t_start1, t_start2,
				t_end1, t_end2
			FROM ca_certificate cac, ca_certificate cac2, ccadb_certificate cc2
			WHERE cac.CERTIFICATE_ID = certificateID
				AND cac.CA_ID = cac2.CA_ID
				AND EXISTS (
					SELECT 1
						FROM certificate c, ca_trust_purpose ctp
						WHERE c.ID = cac2.CERTIFICATE_ID
							AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > statement_timestamp() AT TIME ZONE 'UTC'
							AND c.ISSUER_CA_ID = ctp.CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND ctp.TRUST_PURPOSE_ID >= 100
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
							AND ctp.IS_TIME_VALID
				)
				AND cac2.CERTIFICATE_ID = cc2.CERTIFICATE_ID
				AND cc2.CCADB_RECORD_ID IS NOT NULL;	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
		IF FOUND THEN
			IF t_url1 != t_url2 THEN
				t_problems := array_append(t_problems, '"EV SSL Audit" URLs: ' || t_url1 || ' != ' || t_url2);
			END IF;
			IF t_type1 != t_type2 THEN
				t_problems := array_append(t_problems, '"EV SSL Audit Type"s: ' || t_type1 || ' != ' || t_type2);
			END IF;
			IF t_date1 != t_date2 THEN
				t_problems := array_append(t_problems, '"EV SSL Audit Statement Date"s: ' || t_date1 || ' != ' || t_date2);
			END IF;
			IF t_start1 != t_start2 THEN
				t_problems := array_append(t_problems, '"EV SSL Audit Period Start Date"s: ' || t_start1 || ' != ' || t_start2);
			END IF;
			IF t_end1 != t_end2 THEN
				t_problems := array_append(t_problems, '"EV SSL Audit Period End Date"s: ' || t_end1 || ' != ' || t_end2);
			END IF;
		END IF;

	ELSIF t_disclosureStatus = 'DisclosedWithInconsistentCPS' THEN
		SELECT min(coalesce(cc2.CP_URL, '&lt;omitted&gt;')), max(coalesce(cc2.CP_URL, '&lt;omitted&gt;')),
				min(coalesce(cc2.CPS_URL, '&lt;omitted&gt;')), max(coalesce(cc2.CPS_URL, '&lt;omitted&gt;'))
			INTO t_url1, t_url2,
				t_type1, t_type2
			FROM ca_certificate cac, ca_certificate cac2, ccadb_certificate cc2
			WHERE cac.CERTIFICATE_ID = certificateID
				AND cac.CA_ID = cac2.CA_ID
				AND EXISTS (
					SELECT 1
						FROM certificate c, ca_trust_purpose ctp
						WHERE c.ID = cac2.CERTIFICATE_ID
							AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > statement_timestamp() AT TIME ZONE 'UTC'
							AND c.ISSUER_CA_ID = ctp.CA_ID
							AND ctp.TRUST_CONTEXT_ID = trustContextID
							AND NOT ctp.ALL_CHAINS_REVOKED_IN_SALESFORCE
							AND ctp.IS_TIME_VALID
				)
				AND cac2.CERTIFICATE_ID = cc2.CERTIFICATE_ID
				AND cc2.CCADB_RECORD_ID IS NOT NULL;	-- Ignore CA certificates not in CCADB (e.g., kernel mode cross-certificates).
		IF sort_delimited_list(t_url1, ';') != sort_delimited_list(t_url2, ';') THEN
			t_problems := array_append(t_problems, '"Certificate Policy (CP)" URLs: ' || t_url1 || ' != ' || t_url2);
		END IF;
		IF sort_delimited_list(t_type1, ';') != sort_delimited_list(t_type2, ';') THEN
			t_problems := array_append(t_problems, '"Certification Practice Statement (CPS)" URLs: ' || t_type1 || ' != ' || t_type2);
		END IF;

	END IF;

	RETURN t_problems;
END;
$$ LANGUAGE plpgsql;
