CREATE TABLE cablint_1week_summary_temp AS
SELECT c.ISSUER_CA_ID,
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
	FROM certificate c, ca
	WHERE x509_notBefore(c.CERTIFICATE) >= date_trunc('day', statement_timestamp() - interval '1 week')
		AND c.ISSUER_CA_ID = ca.ID
		AND ca.CABLINT_APPLIES
	GROUP BY c.ISSUER_CA_ID;

UPDATE cablint_1week_summary_temp c1st
	SET ALL_CERTS = sub.ALL_CERTS,
		ALL_ISSUES = sub.ALL_ISSUES
	FROM (
		SELECT count(DISTINCT cci.CERTIFICATE_ID) ALL_CERTS,
				count(*) ALL_ISSUES,
				cci.ISSUER_CA_ID
			FROM cablint_cert_issue cci, cablint_issue ci
			WHERE cci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND cci.CABLINT_ISSUE_ID = ci.ID
				AND ci.SEVERITY NOT IN ('I', 'B')
			GROUP BY cci.ISSUER_CA_ID
		) sub
	WHERE c1st.ISSUER_CA_ID = sub.ISSUER_CA_ID;

UPDATE cablint_1week_summary_temp c1st
	SET FATAL_CERTS = sub.FATAL_CERTS,
		FATAL_ISSUES = sub.FATAL_ISSUES
	FROM (
		SELECT count(DISTINCT cci.CERTIFICATE_ID) FATAL_CERTS,
				count(*) FATAL_ISSUES,
				cci.ISSUER_CA_ID
			FROM cablint_cert_issue cci, cablint_issue ci
			WHERE cci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND cci.CABLINT_ISSUE_ID = ci.ID
				AND ci.SEVERITY = 'F'
			GROUP BY cci.ISSUER_CA_ID
		) sub
	WHERE c1st.ISSUER_CA_ID = sub.ISSUER_CA_ID;

UPDATE cablint_1week_summary_temp c1st
	SET ERROR_CERTS = sub.ERROR_CERTS,
		ERROR_ISSUES = sub.ERROR_ISSUES
	FROM (
		SELECT count(DISTINCT cci.CERTIFICATE_ID) ERROR_CERTS,
				count(*) ERROR_ISSUES,
				cci.ISSUER_CA_ID
			FROM cablint_cert_issue cci, cablint_issue ci
			WHERE cci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND cci.CABLINT_ISSUE_ID = ci.ID
				AND ci.SEVERITY = 'E'
			GROUP BY cci.ISSUER_CA_ID
		) sub
	WHERE c1st.ISSUER_CA_ID = sub.ISSUER_CA_ID;

UPDATE cablint_1week_summary_temp c1st
	SET WARNING_CERTS = sub.WARNING_CERTS,
		WARNING_ISSUES = sub.WARNING_ISSUES
	FROM (
		SELECT count(DISTINCT cci.CERTIFICATE_ID) WARNING_CERTS,
				count(*) WARNING_ISSUES,
				cci.ISSUER_CA_ID
			FROM cablint_cert_issue cci, cablint_issue ci
			WHERE cci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND cci.CABLINT_ISSUE_ID = ci.ID
				AND ci.SEVERITY = 'W'
			GROUP BY cci.ISSUER_CA_ID
		) sub
	WHERE c1st.ISSUER_CA_ID = sub.ISSUER_CA_ID;

UPDATE cablint_1week_summary_temp c1st
	SET NOTICE_CERTS = sub.NOTICE_CERTS,
		NOTICE_ISSUES = sub.NOTICE_ISSUES
	FROM (
		SELECT count(DISTINCT cci.CERTIFICATE_ID) NOTICE_CERTS,
				count(*) NOTICE_ISSUES,
				cci.ISSUER_CA_ID
			FROM cablint_cert_issue cci, cablint_issue ci
			WHERE cci.NOT_BEFORE >= date_trunc('day', statement_timestamp() - interval '1 week')
				AND cci.CABLINT_ISSUE_ID = ci.ID
				AND ci.SEVERITY = 'N'
			GROUP BY cci.ISSUER_CA_ID
		) sub
	WHERE c1st.ISSUER_CA_ID = sub.ISSUER_CA_ID;

ANALYZE cablint_1week_summary_temp;

GRANT SELECT ON cablint_1week_summary_temp TO httpd;

DROP TABLE cablint_1week_summary;

ALTER TABLE cablint_1week_summary_temp RENAME TO cablint_1week_summary;
