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

CREATE OR REPLACE FUNCTION cablint_cached(
	cert_id					certificate.ID%TYPE
) RETURNS SETOF cablint_issue.ID%TYPE
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_cablintDeployedAt	cablint_version.DEPLOYED_AT%TYPE;
	t_cablintCachedAt	certificate.CABLINT_CACHED_AT%TYPE;
	t_cablintIssueID	cablint_issue.ID%TYPE;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_count				integer;
	l_record			RECORD;
BEGIN
	SELECT c.CERTIFICATE, c.CABLINT_CACHED_AT, c.ISSUER_CA_ID
		INTO t_certificate, t_cablintCachedAt, t_issuerCAID
		FROM certificate c
		WHERE c.ID = cert_id;
	IF NOT FOUND THEN
		RETURN;
	END IF;

	SELECT max(cv.DEPLOYED_AT)
		INTO t_cablintDeployedAt
		FROM cablint_version cv;

	IF coalesce(t_cablintCachedAt, t_cablintDeployedAt) > t_cablintDeployedAt THEN
		RETURN QUERY
			SELECT cci.cablint_issue_id
				FROM cablint_cert_issue cci
				WHERE cci.CERTIFICATE_ID = cert_id;
	ELSE
		DELETE FROM cablint_cert_issue cci
			WHERE cci.CERTIFICATE_ID = cert_id;

		t_count := 0;
		FOR l_record IN (
					SELECT cablint_embedded(t_certificate) CABLINT
				) LOOP
			t_count := t_count + 1;
			SELECT ci.ID
				INTO t_cablintIssueID
				FROM cablint_issue ci
				WHERE ci.SEVERITY = substr(l_record.CABLINT, 1, 1)
					AND ci.ISSUE_TEXT = substr(l_record.CABLINT, 4);
			IF NOT FOUND THEN
				INSERT INTO cablint_issue (
						SEVERITY, ISSUE_TEXT
					)
					VALUES (
						substr(l_record.CABLINT, 1, 1), substr(l_record.CABLINT, 4)
					)
					RETURNING ID
						INTO t_cablintIssueID;
			END IF;
			INSERT INTO cablint_cert_issue (
					CERTIFICATE_ID, CABLINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE
				)
				VALUES (
					cert_id, t_cablintIssueID, t_issuerCAID, x509_notBefore(t_certificate)
				);
			RETURN NEXT t_cablintIssueID;
		END LOOP;

		IF t_count > 0 THEN
			UPDATE certificate
				SET CABLINT_CACHED_AT = statement_timestamp()
				WHERE ID = cert_id;
		END IF;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
