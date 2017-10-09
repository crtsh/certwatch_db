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

CREATE OR REPLACE FUNCTION lint_cached(
	cert_id					certificate.ID%TYPE,
	v_linter				linter_type
) RETURNS SETOF lint_issue.ID%TYPE
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_linterDeployedAt	linter_version.DEPLOYED_AT%TYPE;
	t_lintCachedAt		timestamp;
	t_lintIssueID		lint_issue.ID%TYPE;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_query				text;
	t_certType			integer;
	t_count				integer;
	l_record			RECORD;
BEGIN
	SELECT c.CERTIFICATE, c.ISSUER_CA_ID,
			CASE v_linter
				WHEN 'cablint' THEN c.CABLINT_CACHED_AT AT TIME ZONE 'UTC'
				WHEN 'x509lint' THEN c.X509LINT_CACHED_AT AT TIME ZONE 'UTC'
				WHEN 'zlint' THEN c.ZLINT_CACHED_AT AT TIME ZONE 'UTC'
			END
		INTO t_certificate, t_issuerCAID,
			t_lintCachedAt
		FROM certificate c
		WHERE c.ID = cert_id;
	IF NOT FOUND THEN
		RETURN;
	END IF;

	SELECT max(lv.DEPLOYED_AT AT TIME ZONE 'UTC')
		INTO t_linterDeployedAt
		FROM linter_version lv
		WHERE lv.LINTER = v_linter;

	IF coalesce(t_lintCachedAt, t_linterDeployedAt) > t_linterDeployedAt THEN
		RETURN QUERY
			SELECT lci.LINT_ISSUE_ID
				FROM lint_cert_issue lci, lint_issue li
				WHERE lci.CERTIFICATE_ID = cert_id
					AND lci.LINT_ISSUE_ID = li.ID
					AND li.LINTER = v_linter;
	ELSE
		DELETE FROM lint_cert_issue lci
			USING lint_issue li
			WHERE lci.CERTIFICATE_ID = cert_id
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.LINTER = v_linter;

		IF v_linter = 'cablint' THEN
			t_query := 'SELECT cablint_embedded($1) LINT';
		ELSIF v_linter = 'x509lint' THEN
			t_query := 'SELECT x509lint_embedded($1,$2) LINT';
			IF NOT x509_canIssueCerts(t_certificate) THEN
				t_certType := 0;
			ELSE
				SELECT count(*)
					INTO t_count
					FROM ca_certificate cac
					WHERE cac.CERTIFICATE_ID = cert_id
						AND cac.CA_ID = t_issuerCAID;
				IF t_count = 0 THEN
					t_certType := 1;
				ELSE
					t_certType := 2;
				END IF;
			END IF;
		ELSIF v_linter = 'zlint' THEN
			t_query := 'SELECT zlint_embedded($1) LINT';
		END IF;

		FOR l_record IN EXECUTE t_query USING t_certificate, t_certType LOOP
			IF substr(l_record.LINT, 1, 1) IN ('W', 'E', 'F') THEN
				SELECT li.ID
					INTO t_lintIssueID
					FROM lint_issue li
					WHERE li.LINTER = v_linter
						AND li.SEVERITY = substr(l_record.LINT, 1, 1)
						AND li.ISSUE_TEXT = substr(l_record.LINT, 4);
				IF NOT FOUND THEN
					BEGIN
						INSERT INTO lint_issue (
								LINTER, SEVERITY, ISSUE_TEXT
							)
							VALUES (
								v_linter, substr(l_record.LINT, 1, 1), substr(l_record.LINT, 4)
							)
							RETURNING ID
								INTO t_lintIssueID;
					EXCEPTION
						WHEN unique_violation THEN
							SELECT li.ID
								INTO t_lintIssueID
								FROM lint_issue li
								WHERE li.LINTER = v_linter
									AND li.SEVERITY = substr(l_record.LINT, 1, 1)
									AND li.ISSUE_TEXT = substr(l_record.LINT, 4);
					END;
				END IF;
				INSERT INTO lint_cert_issue (
						CERTIFICATE_ID, lint_issue_ID, ISSUER_CA_ID, NOT_BEFORE_DATE
					)
					VALUES (
						cert_id, t_lintIssueID, t_issuerCAID, x509_notBefore(t_certificate)::date
					);
				RETURN NEXT t_lintIssueID;
			END IF;
		END LOOP;

		IF v_linter = 'cablint' THEN
			UPDATE certificate
				SET CABLINT_CACHED_AT = statement_timestamp() AT TIME ZONE 'UTC'
				WHERE ID = cert_id;
		ELSIF v_linter = 'x509lint' THEN
			UPDATE certificate
				SET X509LINT_CACHED_AT = statement_timestamp() AT TIME ZONE 'UTC'
				WHERE ID = cert_id;
		ELSIF v_linter = 'zlint' THEN
			UPDATE certificate
				SET ZLINT_CACHED_AT = statement_timestamp() AT TIME ZONE 'UTC'
				WHERE ID = cert_id;
		END IF;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
