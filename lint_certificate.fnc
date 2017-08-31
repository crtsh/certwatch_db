CREATE OR REPLACE FUNCTION lint_certificate(
	cert					bytea,
	has_dummy_signature		boolean
) RETURNS text
AS $$
DECLARE
	t_header				text;
	t_certType				integer;
	t_output				text := '';
	l_linter				RECORD;
BEGIN
	IF NOT x509_canIssueCerts(cert) THEN
		t_certType := 0;	-- Leaf certificate.
	ELSIF (x509_subjectName(cert) = x509_issuerName(cert))
			AND x509_verify(cert, x509_publicKey(cert)) THEN
		t_certType := 2;	-- Root certificate.
	ELSE
		t_certType := 1;	-- Intermediate certificate.
	END IF;

	FOR l_linter IN (
				SELECT 'cablint' LINTER,
						substr(CABLINT, 1, 2) ISSUE_SEVERITY,
						substr(CABLINT, 4) ISSUE_TEXT,
						CASE substr(CABLINT, 1, 2)
							WHEN 'F:' THEN 1
							WHEN 'E:' THEN 2
							WHEN 'W:' THEN 3
							WHEN 'N:' THEN 4
							WHEN 'I:' THEN 5
							WHEN 'B:' THEN 6
							ELSE 7
						END ISSUE_TYPE
					FROM cablint_embedded(cert) CABLINT
				UNION
				SELECT 'x509lint' LINTER,
						substr(X509LINT, 1, 2) ISSUE_SEVERITY,
						substr(X509LINT, 4) ISSUE_TEXT,
						CASE substr(X509LINT, 1, 2)
							WHEN 'F:' THEN 1
							WHEN 'E:' THEN 2
							WHEN 'W:' THEN 3
							WHEN 'N:' THEN 4
							WHEN 'I:' THEN 5
							WHEN 'B:' THEN 6
							ELSE 7
						END ISSUE_TYPE
					FROM x509lint_embedded(cert, t_certType) X509LINT
				UNION
				SELECT 'zlint' LINTER,
						substr(ZLINT, 1, 2) ISSUE_SEVERITY,
						substr(ZLINT, 4) ISSUE_TEXT,
						CASE substr(ZLINT, 1, 2)
							WHEN 'F:' THEN 1
							WHEN 'E:' THEN 2
							WHEN 'W:' THEN 3
							WHEN 'N:' THEN 4
							WHEN 'I:' THEN 5
							WHEN 'B:' THEN 6
							ELSE 7
						END ISSUE_TYPE
					FROM zlint_embedded(cert) ZLINT
				ORDER BY LINTER, ISSUE_TYPE, ISSUE_TEXT
			) LOOP
		IF has_dummy_signature AND (l_linter.LINTER = 'cablint')
				AND (
					(l_linter.ISSUE_TEXT = 'Certificate signature algorithm does not match TBS signature algorithm')
					 OR (l_linter.ISSUE_TEXT LIKE 'Certificate signature algorithm type is unknown:%')
				) THEN
			NULL;
		ELSE
			t_output := t_output ||
						l_linter.LINTER::text || chr(9) ||
						CASE l_linter.ISSUE_TYPE
							WHEN 1 THEN 'FATAL'
							WHEN 2 THEN 'ERROR'
							WHEN 3 THEN 'WARNING'
							WHEN 4 THEN 'NOTICE'
							WHEN 5 THEN 'INFO'
							WHEN 6 THEN 'BUG'
							ELSE l_linter.ISSUE_SEVERITY
						END || chr(9) ||
						l_linter.ISSUE_TEXT || chr(10);
		END IF;
	END LOOP;

	RETURN t_output;
END;
$$ LANGUAGE plpgsql STRICT;
