CREATE OR REPLACE FUNCTION lint_tbscertificate(
	tbscert					bytea
) RETURNS text
AS $$
DECLARE
	t_certificate			bytea;
	t_header				text;
	t_certType				integer;
	t_output				text := '';
	l_linter				RECORD;
BEGIN
	-- Add ASN.1 packaging and a dummy signature to create a valid X.509
	-- certificate that the linters will parse.
	t_certificate := tbscert || E'\\x3003060100030100';
	t_header := to_hex(length(t_certificate));
	IF length(t_header) % 2 > 0 THEN
		t_header := '0' || t_header;
	END IF;
	IF length(t_header) > 2 THEN
		t_header := to_hex(128 + (length(t_header) / 2)) || t_header;
	END IF;
	t_certificate := E'\\x30' || decode(t_header, 'hex') || t_certificate;

	IF NOT x509_canIssueCerts(t_certificate) THEN
		t_certType := 0;	-- Leaf certificate.
	ELSIF (x509_subjectName(t_certificate) = x509_issuerName(t_certificate))
			AND x509_verify(t_certificate, x509_publicKey(t_certificate)) THEN
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
					FROM cablint_embedded(t_certificate) CABLINT
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
					FROM x509lint_embedded(t_certificate, t_certType) X509LINT
				ORDER BY LINTER, ISSUE_TYPE, ISSUE_TEXT
			) LOOP
		IF (l_linter.LINTER = 'cablint')
				AND (
					(l_linter.ISSUE_TEXT = 'Certificate signature algorithm does not match TBS signature algorithm')
					 OR (l_linter.ISSUE_TEXT LIKE 'Certificate signature algorithm type is unknown:%')
				) THEN
			NULL;
		ELSE
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
		END IF;
	END LOOP;

	RETURN t_output;
END;
$$ LANGUAGE plpgsql STRICT;
