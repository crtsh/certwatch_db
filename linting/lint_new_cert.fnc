CREATE OR REPLACE FUNCTION lint_new_cert(
	_cert_id				certificate.ID%TYPE,
	_issuer_ca_id			ca.ID%TYPE,
	_certificate			certificate.CERTIFICATE%TYPE,
	_cert_type				integer,
	_linter					linter_type
) RETURNS void
AS $$
DECLARE
	t_lintIssueID		lint_issue.ID%TYPE;
	t_query				text;
	l_record			RECORD;
BEGIN
	IF _linter = 'cablint' THEN
		t_query := 'SELECT cablint_embedded($1) LINT';
	ELSIF _linter = 'x509lint' THEN
		t_query := 'SELECT x509lint_embedded($1,$2) LINT';
	ELSIF _linter = 'zlint' THEN
		t_query := 'SELECT zlint_embedded($1) LINT';
	END IF;

	FOR l_record IN EXECUTE t_query USING _certificate, _cert_type LOOP
		IF substr(l_record.LINT, 1, 1) IN ('W', 'E', 'F') THEN
			SELECT li.ID
				INTO t_lintIssueID
				FROM lint_issue li
				WHERE li.LINTER = _linter
					AND li.SEVERITY = substr(l_record.LINT, 1, 1)
					AND li.ISSUE_TEXT = substr(l_record.LINT, 4);
			IF NOT FOUND THEN
				BEGIN
					INSERT INTO lint_issue (
							LINTER, SEVERITY, ISSUE_TEXT
						)
						VALUES (
							_linter, substr(l_record.LINT, 1, 1), substr(l_record.LINT, 4)
						)
						RETURNING ID
							INTO t_lintIssueID;
				EXCEPTION
					WHEN unique_violation THEN
						SELECT li.ID
							INTO t_lintIssueID
							FROM lint_issue li
							WHERE li.LINTER = _linter
								AND li.SEVERITY = substr(l_record.LINT, 1, 1)
								AND li.ISSUE_TEXT = substr(l_record.LINT, 4);
				END;
			END IF;
			BEGIN
				INSERT INTO lint_cert_issue (
						CERTIFICATE_ID, LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE
					)
					VALUES (
						_cert_id, t_lintIssueID, _issuer_ca_id, x509_notBefore(_certificate)::date
					);
			EXCEPTION
				WHEN unique_violation THEN
					NULL;
			END;
		END IF;
	END LOOP;
END;
$$ LANGUAGE plpgsql STRICT;
