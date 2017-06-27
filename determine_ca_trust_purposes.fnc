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

CREATE OR REPLACE FUNCTION determine_ca_trust_purposes(
	max_iterations			integer		DEFAULT 20
) RETURNS integer
AS $$
DECLARE
	t_iteration					integer		:= 1;
	t_nothingChanged			boolean;
	t_isTrusted					boolean;
	t_count						integer;
	t_certPathLenConstraint		integer;
	l_record					RECORD;
	t_ctp_parent				ca_trust_purpose_temp%ROWTYPE;
	t_ctp_old					ca_trust_purpose_temp%ROWTYPE;
	t_ctp_new					ca_trust_purpose_temp%ROWTYPE;
BEGIN
	INSERT INTO ca_trust_purpose_temp (
			CA_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID,
			SHORTEST_CHAIN, ITERATION_LAST_MODIFIED, PATH_LEN_CONSTRAINT,
			IS_TIME_VALID
		)
		SELECT cac.CA_ID, rtp.TRUST_CONTEXT_ID, rtp.TRUST_PURPOSE_ID,
				1, 0, 999,
				(statement_timestamp() BETWEEN min(x509_notBefore(c.CERTIFICATE)) AND max(x509_notAfter(c.CERTIFICATE)))
			FROM root_trust_purpose rtp, ca_certificate cac, certificate c
			WHERE rtp.CERTIFICATE_ID = cac.CERTIFICATE_ID
				AND cac.CERTIFICATE_ID = c.ID
			GROUP BY cac.CA_ID, rtp.TRUST_CONTEXT_ID,
					rtp.TRUST_PURPOSE_ID;
	UPDATE ca_trust_purpose_temp
		SET ALL_CHAINS_TECHNICALLY_CONSTRAINED = FALSE,
			ALL_CHAINS_REVOKED_IN_SALESFORCE = FALSE,
			ALL_CHAINS_REVOKED_VIA_ONECRL = FALSE,
			ALL_CHAINS_REVOKED_VIA_CRLSET = FALSE,
			ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL = FALSE
		WHERE IS_TIME_VALID;

	WHILE t_iteration <= max_iterations LOOP
		t_nothingChanged := TRUE;

		FOR l_record IN (
					SELECT ctp.TRUST_CONTEXT_ID, ctp.TRUST_PURPOSE_ID,
							tp.PURPOSE, tp.PURPOSE_OID,
							c.ID, c.CERTIFICATE, c.ISSUER_CA_ID, cac.CA_ID
						FROM ca_trust_purpose_temp ctp, trust_purpose tp,
							certificate c, ca_certificate cac
						WHERE ctp.ITERATION_LAST_MODIFIED = t_iteration - 1
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND ctp.CA_ID = c.ISSUER_CA_ID
							AND x509_canIssueCerts(c.CERTIFICATE)
							AND c.ID = cac.CERTIFICATE_ID
							AND ctp.CA_ID != cac.CA_ID
				) LOOP
			t_isTrusted := FALSE;
			IF l_record.PURPOSE = 'EV Server Authentication' THEN
				IF x509_isPolicyPermitted(l_record.CERTIFICATE,
											l_record.PURPOSE_OID) THEN
					IF x509_isEKUPermitted(l_record.CERTIFICATE,
											'1.3.6.1.5.5.7.3.1')
							OR x509_isEKUPermitted(l_record.CERTIFICATE,
											'1.3.6.1.4.1.311.10.3.3') THEN
						-- This EV Policy OID is permitted, and so is Server
						-- Authentication and/or SGC.
						t_isTrusted := TRUE;
					END IF;
				END IF;
			ELSIF x509_isEKUPermitted(l_record.CERTIFICATE,
										l_record.PURPOSE_OID) THEN
				t_isTrusted := TRUE;
			ELSIF (l_record.PURPOSE_OID = '1.3.6.1.5.5.7.3.1')
					AND x509_isEKUPermitted(l_record.CERTIFICATE,
											'1.3.6.1.4.1.311.10.3.3') THEN
				-- If SGC is present but Server Authentication is not
				-- present, act as if Server Authentication is present.
				t_isTrusted := TRUE;
			END IF;
			CONTINUE WHEN (NOT t_isTrusted);

			t_certPathLenConstraint := x509_getPathLenConstraint(l_record.CERTIFICATE);
			CONTINUE WHEN (coalesce(t_certPathLenConstraint, 0) < 0);

			SELECT ctp.*
				INTO t_ctp_parent
				FROM ca_trust_purpose_temp ctp
				WHERE ctp.CA_ID = l_record.ISSUER_CA_ID
					AND ctp.TRUST_CONTEXT_ID = l_record.TRUST_CONTEXT_ID
					AND ctp.TRUST_PURPOSE_ID = l_record.TRUST_PURPOSE_ID;

			SELECT ctp.*
				INTO t_ctp_old
				FROM ca_trust_purpose_temp ctp
				WHERE ctp.CA_ID = l_record.CA_ID
					AND ctp.TRUST_CONTEXT_ID = l_record.TRUST_CONTEXT_ID
					AND ctp.TRUST_PURPOSE_ID = l_record.TRUST_PURPOSE_ID;
			IF FOUND THEN
				t_ctp_new := t_ctp_old;
			ELSE
				t_ctp_new.CA_ID := NULL;
				t_ctp_new.PATH_LEN_CONSTRAINT := 0;
				t_ctp_new.IS_TIME_VALID := FALSE;
				t_ctp_new.ALL_CHAINS_TECHNICALLY_CONSTRAINED := NULL;
				t_ctp_new.ALL_CHAINS_REVOKED_IN_SALESFORCE := NULL;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_CRLSET := NULL;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_ONECRL := NULL;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL := NULL;
			END IF;

			t_ctp_new.PATH_LEN_CONSTRAINT := greatest(
				t_ctp_new.PATH_LEN_CONSTRAINT,
				least(
					t_ctp_parent.PATH_LEN_CONSTRAINT - 1,
					coalesce(t_certPathLenConstraint, 999)
				)
			);

			IF t_ctp_parent.IS_TIME_VALID AND (statement_timestamp() BETWEEN x509_notBefore(l_record.CERTIFICATE) AND x509_notAfter(l_record.CERTIFICATE)) THEN
				t_ctp_new.IS_TIME_VALID := TRUE;

				t_ctp_new.ALL_CHAINS_TECHNICALLY_CONSTRAINED := least(
					t_ctp_new.ALL_CHAINS_TECHNICALLY_CONSTRAINED,
					greatest(
						t_ctp_parent.ALL_CHAINS_TECHNICALLY_CONSTRAINED,
						is_technically_constrained(l_record.CERTIFICATE)
					)
				);

				SELECT count(*)
					INTO t_count
					FROM ccadb_certificate cc
					WHERE cc.CERTIFICATE_ID = l_record.ID
						AND cc.DISCLOSURE_STATUS IN ('Revoked', 'RevokedViaOneCRL');
				t_ctp_new.ALL_CHAINS_REVOKED_IN_SALESFORCE := least(
					t_ctp_new.ALL_CHAINS_REVOKED_IN_SALESFORCE,
					greatest(
						t_ctp_parent.ALL_CHAINS_REVOKED_IN_SALESFORCE,
						(t_count > 0)
					)
				);

				SELECT count(*)
					INTO t_count
					FROM mozilla_onecrl mo
					WHERE mo.CERTIFICATE_ID = l_record.ID;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_ONECRL := least(
					t_ctp_new.ALL_CHAINS_REVOKED_VIA_ONECRL,
					greatest(
						t_ctp_parent.ALL_CHAINS_REVOKED_VIA_ONECRL,
						(t_count > 0)
					)
				);

				SELECT count(*)
					INTO t_count
					FROM google_revoked gr
					WHERE gr.CERTIFICATE_ID = l_record.ID;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_CRLSET := least(
					t_ctp_new.ALL_CHAINS_REVOKED_VIA_CRLSET,
					greatest(
						t_ctp_parent.ALL_CHAINS_REVOKED_VIA_CRLSET,
						(t_count > 0)
					)
				);

				SELECT count(*)
					INTO t_count
					FROM microsoft_disallowedcert mdc
					WHERE mdc.CERTIFICATE_ID = l_record.ID;
				t_ctp_new.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL := least(
					t_ctp_new.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL,
					greatest(
						t_ctp_parent.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL,
						(t_count > 0)
					)
				);
			END IF;

			IF t_ctp_new.CA_ID IS NULL THEN
				t_nothingChanged := FALSE;
				INSERT INTO ca_trust_purpose_temp (
						CA_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID,
						SHORTEST_CHAIN, ITERATION_LAST_MODIFIED, PATH_LEN_CONSTRAINT,
						IS_TIME_VALID, ALL_CHAINS_TECHNICALLY_CONSTRAINED,
						ALL_CHAINS_REVOKED_IN_SALESFORCE, ALL_CHAINS_REVOKED_VIA_ONECRL,
						ALL_CHAINS_REVOKED_VIA_CRLSET, ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
					)
					VALUES (
						l_record.CA_ID, l_record.TRUST_CONTEXT_ID, l_record.TRUST_PURPOSE_ID,
						t_iteration + 1, t_iteration, t_ctp_new.PATH_LEN_CONSTRAINT,
						t_ctp_new.IS_TIME_VALID, t_ctp_new.ALL_CHAINS_TECHNICALLY_CONSTRAINED,
						t_ctp_new.ALL_CHAINS_REVOKED_IN_SALESFORCE, t_ctp_new.ALL_CHAINS_REVOKED_VIA_ONECRL,
						t_ctp_new.ALL_CHAINS_REVOKED_VIA_CRLSET, t_ctp_new.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
					);
			ELSE
				IF t_ctp_old <> t_ctp_new THEN
					t_nothingChanged := FALSE;
					UPDATE ca_trust_purpose_temp
						SET ITERATION_LAST_MODIFIED = t_iteration,
							PATH_LEN_CONSTRAINT = t_ctp_new.PATH_LEN_CONSTRAINT,
							IS_TIME_VALID = t_ctp_new.IS_TIME_VALID,
							ALL_CHAINS_TECHNICALLY_CONSTRAINED = t_ctp_new.ALL_CHAINS_TECHNICALLY_CONSTRAINED,
							ALL_CHAINS_REVOKED_IN_SALESFORCE = t_ctp_new.ALL_CHAINS_REVOKED_IN_SALESFORCE,
							ALL_CHAINS_REVOKED_VIA_ONECRL = t_ctp_new.ALL_CHAINS_REVOKED_VIA_ONECRL,
							ALL_CHAINS_REVOKED_VIA_CRLSET = t_ctp_new.ALL_CHAINS_REVOKED_VIA_CRLSET,
							ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL = t_ctp_new.ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL
						WHERE CA_ID = l_record.CA_ID
							AND TRUST_CONTEXT_ID = l_record.TRUST_CONTEXT_ID
							AND TRUST_PURPOSE_ID = l_record.TRUST_PURPOSE_ID;
				END IF;
			END IF;
		END LOOP;

		EXIT WHEN t_nothingChanged;
		t_iteration := t_iteration + 1;
	END LOOP;

	RETURN t_iteration;
END;
$$ LANGUAGE plpgsql;
