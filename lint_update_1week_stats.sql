CREATE TABLE lint_1week_summary_temp AS
SELECT linter,
		c.ISSUER_CA_ID,
		count(*)::bigint CERTS_ISSUED,
		0::bigint ALL_CERTS,
		0::bigint ALL_ISSUES,
		0::bigint FATAL_CERTS,
		0::bigint FATAL_ISSUES,
		0::bigint ERROR_CERTS,
		0::bigint ERROR_ISSUES,
		0::bigint WARNING_CERTS,
		0::bigint WARNING_ISSUES,
		0::bigint NOTICE_CERTS,
		0::bigint NOTICE_ISSUES
	FROM certificate c, ca, unnest(array_append(enum_range(NULL::linter_type), NULL)) linter
	WHERE x509_notBefore(c.CERTIFICATE) >= date_trunc('day', statement_timestamp() - interval '1 week')
		AND c.ISSUER_CA_ID = ca.ID
		AND ca.LINTING_APPLIES
	GROUP BY linter, c.ISSUER_CA_ID;

UPDATE lint_1week_summary_temp l1st
	SET ALL_CERTS = sub.ALL_CERTS,
		ALL_ISSUES = sub.ALL_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) ALL_CERTS,
				count(*) ALL_ISSUES,
				lci.ISSUER_CA_ID,
				li.LINTER
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY NOT IN ('I', 'B')
			GROUP BY lci.ISSUER_CA_ID, li.LINTER
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER = sub.LINTER;
UPDATE lint_1week_summary_temp l1st
	SET ALL_CERTS = sub.ALL_CERTS,
		ALL_ISSUES = sub.ALL_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) ALL_CERTS,
				count(*) ALL_ISSUES,
				lci.ISSUER_CA_ID
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY NOT IN ('I', 'B')
			GROUP BY lci.ISSUER_CA_ID
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER IS NULL;

UPDATE lint_1week_summary_temp l1st
	SET FATAL_CERTS = sub.FATAL_CERTS,
		FATAL_ISSUES = sub.FATAL_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) FATAL_CERTS,
				count(*) FATAL_ISSUES,
				lci.ISSUER_CA_ID,
				li.LINTER
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'F'
			GROUP BY lci.ISSUER_CA_ID, li.LINTER
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER = sub.LINTER;
UPDATE lint_1week_summary_temp l1st
	SET FATAL_CERTS = sub.FATAL_CERTS,
		FATAL_ISSUES = sub.FATAL_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) FATAL_CERTS,
				count(*) FATAL_ISSUES,
				lci.ISSUER_CA_ID
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'F'
			GROUP BY lci.ISSUER_CA_ID
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER IS NULL;

UPDATE lint_1week_summary_temp l1st
	SET ERROR_CERTS = sub.ERROR_CERTS,
		ERROR_ISSUES = sub.ERROR_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) ERROR_CERTS,
				count(*) ERROR_ISSUES,
				lci.ISSUER_CA_ID,
				li.LINTER
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'E'
			GROUP BY lci.ISSUER_CA_ID, li.LINTER
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER = sub.LINTER;
UPDATE lint_1week_summary_temp l1st
	SET ERROR_CERTS = sub.ERROR_CERTS,
		ERROR_ISSUES = sub.ERROR_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) ERROR_CERTS,
				count(*) ERROR_ISSUES,
				lci.ISSUER_CA_ID
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'E'
			GROUP BY lci.ISSUER_CA_ID
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER IS NULL;

UPDATE lint_1week_summary_temp l1st
	SET WARNING_CERTS = sub.WARNING_CERTS,
		WARNING_ISSUES = sub.WARNING_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) WARNING_CERTS,
				count(*) WARNING_ISSUES,
				lci.ISSUER_CA_ID,
				li.LINTER
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'W'
			GROUP BY lci.ISSUER_CA_ID, li.LINTER
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER = sub.LINTER;
UPDATE lint_1week_summary_temp l1st
	SET WARNING_CERTS = sub.WARNING_CERTS,
		WARNING_ISSUES = sub.WARNING_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) WARNING_CERTS,
				count(*) WARNING_ISSUES,
				lci.ISSUER_CA_ID
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'W'
			GROUP BY lci.ISSUER_CA_ID
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER IS NULL;

UPDATE lint_1week_summary_temp l1st
	SET NOTICE_CERTS = sub.NOTICE_CERTS,
		NOTICE_ISSUES = sub.NOTICE_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) NOTICE_CERTS,
				count(*) NOTICE_ISSUES,
				lci.ISSUER_CA_ID,
				li.LINTER
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'N'
			GROUP BY lci.ISSUER_CA_ID, li.LINTER
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER = sub.LINTER;
UPDATE lint_1week_summary_temp l1st
	SET NOTICE_CERTS = sub.NOTICE_CERTS,
		NOTICE_ISSUES = sub.NOTICE_ISSUES
	FROM (
		SELECT count(DISTINCT lci.CERTIFICATE_ID) NOTICE_CERTS,
				count(*) NOTICE_ISSUES,
				lci.ISSUER_CA_ID
			FROM lint_cert_issue lci, lint_issue li
			WHERE lci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND lci.LINT_ISSUE_ID = li.ID
				AND li.SEVERITY = 'N'
			GROUP BY lci.ISSUER_CA_ID
		) sub
	WHERE l1st.ISSUER_CA_ID = sub.ISSUER_CA_ID
		AND l1st.LINTER IS NULL;

ANALYZE lint_1week_summary_temp;

GRANT SELECT ON lint_1week_summary_temp TO httpd;

GRANT SELECT ON lint_1week_summary_temp TO guest;

DROP TABLE lint_1week_summary;

ALTER TABLE lint_1week_summary_temp RENAME TO lint_1week_summary;
