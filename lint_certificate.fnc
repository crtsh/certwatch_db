CREATE OR REPLACE FUNCTION lint_certificate(
	cert					bytea
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
							WHEN 'B:' THEN 1
							WHEN 'I:' THEN 2
							WHEN 'N:' THEN 3
							WHEN 'F:' THEN 4
							WHEN 'E:' THEN 5
							WHEN 'W:' THEN 6
							ELSE 5
						END ISSUE_TYPE
					FROM cablint_embedded(cert) CABLINT
				UNION
				SELECT 'x509lint' LINTER,
						substr(X509LINT, 1, 2) ISSUE_SEVERITY,
						substr(X509LINT, 4) ISSUE_TEXT,
						CASE substr(X509LINT, 1, 2)
							WHEN 'B:' THEN 1
							WHEN 'I:' THEN 2
							WHEN 'N:' THEN 3
							WHEN 'F:' THEN 4
							WHEN 'E:' THEN 5
							WHEN 'W:' THEN 6
							ELSE 5
						END ISSUE_TYPE
					FROM x509lint_embedded(cert, t_certType) X509LINT
				ORDER BY LINTER, ISSUE_TYPE, ISSUE_TEXT
			) LOOP
		t_output := t_output ||
					l_linter.LINTER::text || chr(9) ||
					CASE l_linter.ISSUE_TYPE
						WHEN 1 THEN 'BUG'
						WHEN 2 THEN 'INFO'
						WHEN 3 THEN 'NOTICE'
						WHEN 4 THEN 'FATAL'
						WHEN 5 THEN 'ERROR'
						WHEN 6 THEN 'WARNING'
						ELSE l_linter.ISSUE_SEVERITY
					END || chr(9) ||
					l_linter.ISSUE_TEXT || chr(10);
	END LOOP;

	RETURN t_output;
END;
$$ LANGUAGE plpgsql STRICT;
