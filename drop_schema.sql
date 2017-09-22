DROP FUNCTION web_apis(
	name					text,
	paramNames				text[],
	paramValues				text[]
);

DROP FUNCTION import_ct_cert(
	ct_log_id				ct_log.ID%TYPE,
	ct_log_entry_id			ct_log_entry.ENTRY_ID%TYPE,
	ct_log_timestamp		bigint,
	cert_data				bytea
);

DROP FUNCTION import_cert(
	cert_data				bytea
);

DROP FUNCTION html_escape(
	in_string				text
);

DROP FUNCTION get_parameter(
	parameter				text,
	paramNames				text[],
	paramValues				text[]
);

DROP FUNCTION get_ca_primary_name_attribute(
	ca_id					ca.ID%TYPE,
	cert_data				certificate.CERTIFICATE%TYPE
);

DROP FUNCTION extract_cert_names(
	cert_id					certificate.ID%TYPE,
	issuerca_id				ca.ID%TYPE
);

DROP FUNCTION download_cert(
	cert_id					text
);

DROP FUNCTION lint_cached(
	cert_id					certificate.ID%TYPE,
	v_linter				linter_type
);


DROP TABLE cached_response;

DROP TABLE mozilla_root_hashes;

DROP TABLE mozilla_cert_validation_success;

DROP TABLE mozilla_cert_validation_success_import;

DROP TABLE google_revoked;

DROP TABLE google_crlset_import;

DROP TABLE google_blacklist_import;

DROP TYPE revocation_entry_type;

DROP TABLE microsoft_disallowedcert;

DROP TABLE microsoft_disallowedcert_import;

DROP TABLE ccadb_caowner;

DROP TYPE disclosure_status_type;

DROP TABLE ca_trust_purpose;

DROP TABLE root_trust_purpose;

DROP TABLE applicable_purpose;

DROP TABLE trust_purpose;

DROP TABLE trust_context;

DROP TABLE lint_cert_issue;

DROP TABLE lint_issue;

DROP TABLE linter_version;

DROP TYPE linter_type;

DROP TABLE ct_log_entry;

DROP TABLE ct_log;

DROP TABLE crl_revoked;

DROP TABLE crl;

DROP TABLE ca_certificate;

DROP TABLE certificate_identity;

DROP TYPE name_type;

DROP TABLE invalid_certificate;

DROP TABLE certificate;

DROP TABLE ca;


-- As the "postgres" user.

DROP EXTENSION libzlintpq;

DROP EXTENSION pgcrypto;
