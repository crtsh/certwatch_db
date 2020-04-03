\timing on

\set ON_ERROR_STOP on

DO
$$DECLARE
	t_cablintID						linter_version.ID%TYPE;
	t_x509lintID					linter_version.ID%TYPE;
	t_zlintID						linter_version.ID%TYPE;
	t_certificateID1				certificate.ID%TYPE;
	t_certificateID2				certificate.ID%TYPE;
	t_maxCertificateID				certificate.ID%TYPE;
	t_minCertificateID				certificate.ID%TYPE;
	c_lintingBatchSize	CONSTANT	integer		:= 10000;
	l_issuer						RECORD;
BEGIN
	SELECT lv.ID
		INTO t_cablintID
		FROM linter_version lv
		WHERE lv.LINTER = 'cablint'
		ORDER BY lv.DEPLOYED_AT DESC
		LIMIT 1;
	SELECT lv.ID
		INTO t_x509lintID
		FROM linter_version lv
		WHERE lv.LINTER = 'x509lint'
		ORDER BY lv.DEPLOYED_AT DESC
		LIMIT 1;
	SELECT lv.ID
		INTO t_zlintID
		FROM linter_version lv
		WHERE lv.LINTER = 'zlint'
		ORDER BY lv.DEPLOYED_AT DESC
		LIMIT 1;

	SELECT min(MAX_CERTIFICATE_ID), max(MAX_CERTIFICATE_ID)
		INTO t_certificateID1, t_certificateID2
		FROM linter_version lv
		WHERE lv.ID IN (t_cablintID, t_x509lintID, t_zlintID);
	IF coalesce(t_certificateID1, 0) != coalesce(t_certificateID2, 0) THEN
		RAISE EXCEPTION 'Sorry, the linters are out of sync';
	END IF;

	SELECT max(c.ID)
		INTO t_maxCertificateID
		FROM certificate c;
	IF t_maxCertificateID IS NULL THEN
		RAISE EXCEPTION '"certificate" table is empty';
	END IF;

	IF t_certificateID1 IS NULL THEN
		t_certificateID1 := greatest(t_maxCertificateID - c_lintingBatchSize + 1, 1);
	ELSE
		t_certificateID1 := t_certificateID1 + 1;
	END IF;
	t_certificateID2 := least(t_maxCertificateID, t_certificateID1 + c_lintingBatchSize - 1);

	IF t_certificateID1 < t_certificateID2 THEN
		PERFORM lint_new_cert(c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, 0, 'cablint'),
				lint_new_cert(
					c.ID,
					c.ISSUER_CA_ID,
					c.CERTIFICATE,
					CASE WHEN cac.CA_ID IS NULL THEN 0			-- Leaf certificate.
						WHEN cac.CA_ID = c.ISSUER_CA_ID THEN 2	-- Root certificate.
						ELSE 1									-- Intermediate certificate.
					END,
					'x509lint'
				),
				lint_new_cert(c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, 0, 'zlint')
			FROM certificate c
					LEFT OUTER JOIN ca_certificate cac ON (
						c.ID = cac.CERTIFICATE_ID
					),
				ca
			WHERE c.ID BETWEEN t_certificateID1 AND t_certificateID2
				AND c.ISSUER_CA_ID = ca.ID
				AND ca.LINTING_APPLIES;

		UPDATE linter_version
			SET MIN_CERTIFICATE_ID = coalesce(MIN_CERTIFICATE_ID, t_certificateID1),
				MAX_CERTIFICATE_ID = t_certificateID2
			WHERE ID IN (t_cablintID, t_x509lintID, t_zlintID);

		FOR l_issuer IN (
			SELECT c.ISSUER_CA_ID, x509_notBefore(c.CERTIFICATE)::date NOT_BEFORE_DATE, count(*) AS NEW_CERTS_LINTED
				FROM certificate c, ca
				WHERE c.ID BETWEEN t_certificateID1 AND t_certificateID2
					AND c.ISSUER_CA_ID = ca.ID
					AND ca.LINTING_APPLIES
				GROUP BY c.ISSUER_CA_ID, x509_notBefore(c.CERTIFICATE)::date
		) LOOP
			INSERT INTO lint_summary (
					LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE, NO_OF_CERTS
				)
				VALUES (
					-1, l_issuer.ISSUER_CA_ID, l_issuer.NOT_BEFORE_DATE, l_issuer.NEW_CERTS_LINTED
				)
				ON CONFLICT (LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE) DO UPDATE
					SET NO_OF_CERTS = lint_summary.NO_OF_CERTS + l_issuer.NEW_CERTS_LINTED;
		END LOOP;
	END IF;

	-- (Re-)lint some older "certificate" records.
	SELECT coalesce(lv.MIN_CERTIFICATE_ID, 1) - 1
		INTO t_certificateID2
		FROM linter_version lv
		WHERE lv.ID = t_cablintID;
	IF coalesce(t_certificateID2, 1) > 0 THEN
		t_certificateID1 := greatest(t_certificateID2 - c_lintingBatchSize + 1, 1);

		DELETE FROM lint_cert_issue
			USING lint_issue li
			WHERE CERTIFICATE_ID BETWEEN t_certificateID1 AND t_certificateID2
				AND LINT_ISSUE_ID = li.ID
				AND li.LINTER = 'cablint';

		PERFORM lint_new_cert(c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, 0, 'cablint')
			FROM certificate c, ca
			WHERE c.ID BETWEEN t_certificateID1 AND t_certificateID2
				AND c.ISSUER_CA_ID = ca.ID
				AND ca.LINTING_APPLIES;

		UPDATE linter_version
			SET MIN_CERTIFICATE_ID = t_certificateID1
			WHERE ID = t_cablintID;

		UPDATE linter_version
			SET MAX_CERTIFICATE_ID = t_certificateID1 - 1
			WHERE ID != t_cablintID
				AND LINTER = 'cablint';
	END IF;

	SELECT coalesce(lv.MIN_CERTIFICATE_ID, 1) - 1
		INTO t_certificateID2
		FROM linter_version lv
		WHERE lv.ID = t_x509lintID;
	IF coalesce(t_certificateID2, 1) > 0 THEN
		t_certificateID1 := greatest(t_certificateID2 - c_lintingBatchSize + 1, 1);

		DELETE FROM lint_cert_issue
			USING lint_issue li
			WHERE CERTIFICATE_ID BETWEEN t_certificateID1 AND t_certificateID2
				AND LINT_ISSUE_ID = li.ID
				AND li.LINTER = 'x509lint';

		PERFORM lint_new_cert(
					c.ID,
					c.ISSUER_CA_ID,
					c.CERTIFICATE,
					CASE WHEN cac.CA_ID IS NULL THEN 0			-- Leaf certificate.
						WHEN cac.CA_ID = c.ISSUER_CA_ID THEN 2	-- Root certificate.
						ELSE 1									-- Intermediate certificate.
					END,
					'x509lint'
				)
			FROM certificate c
					LEFT OUTER JOIN ca_certificate cac ON (
						c.ID = cac.CERTIFICATE_ID
					),
				ca
			WHERE c.ID BETWEEN t_certificateID1 AND t_certificateID2
				AND c.ISSUER_CA_ID = ca.ID
				AND ca.LINTING_APPLIES;

		UPDATE linter_version
			SET MIN_CERTIFICATE_ID = t_certificateID1
			WHERE ID = t_x509lintID;

		UPDATE linter_version
			SET MAX_CERTIFICATE_ID = t_certificateID1 - 1
			WHERE ID != t_x509lintID
				AND LINTER = 'x509lint';
	END IF;

	SELECT coalesce(lv.MIN_CERTIFICATE_ID, 1) - 1
		INTO t_certificateID2
		FROM linter_version lv
		WHERE lv.ID = t_zlintID;
	IF coalesce(t_certificateID2, 1) > 0 THEN
		t_certificateID1 := greatest(t_certificateID2 - c_lintingBatchSize + 1, 1);

		DELETE FROM lint_cert_issue
			USING lint_issue li
			WHERE CERTIFICATE_ID BETWEEN t_certificateID1 AND t_certificateID2
				AND LINT_ISSUE_ID = li.ID
				AND li.LINTER = 'zlint';

		PERFORM lint_new_cert(c.ID, c.ISSUER_CA_ID, c.CERTIFICATE, 0, 'zlint')
			FROM certificate c, ca
			WHERE c.ID BETWEEN t_certificateID1 AND t_certificateID2
				AND c.ISSUER_CA_ID = ca.ID
				AND ca.LINTING_APPLIES;

		UPDATE linter_version
			SET MIN_CERTIFICATE_ID = t_certificateID1
			WHERE ID = t_zlintID;

		UPDATE linter_version
			SET MAX_CERTIFICATE_ID = t_certificateID1 - 1
			WHERE ID != t_zlintID
				AND LINTER = 'zlint';
	END IF;

	DELETE FROM linter_version
		WHERE MAX_CERTIFICATE_ID < MIN_CERTIFICATE_ID;
END$$;
