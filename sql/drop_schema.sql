DROP VIEW certificate_lifecycle;

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


DROP TABLE cached_response;

DROP TABLE mozilla_root_hashes;

DROP TABLE mozilla_cert_validation_success;

DROP TABLE mozilla_cert_validation_success_import;

DROP TABLE google_revoked;

DROP TABLE google_crlset_import;

DROP TABLE google_blacklist_import;

DROP TYPE revocation_entry_type;

DROP TABLE microsoft_disallowedcert;

DROP TABLE debian_weak_key;

DROP TYPE debian_rnd_type;

DROP TYPE debian_arch_type;

DROP TABLE ccadb_caowner;

DROP TABLE ccadb_certificate;

DROP TYPE disclosure_status_type;

DROP TABLE ca_trust_purpose;

DROP TABLE root_trust_purpose;

DROP TABLE applicable_purpose;

DROP TABLE trust_purpose;

DROP TABLE trust_context;

DROP TRIGGER lint_summarizer;

DROP FUNCTION lint_summarizer(
);

DROP FUNCTION lint_tbscertificate(
	tbscert					bytea
);

DROP FUNCTION lint_certificate(
	cert					bytea,
	has_dummy_signature		boolean
);

DROP FUNCTION lint_new_cert(
	_cert_id				certificate.ID%TYPE,
	_issuer_ca_id			ca.ID%TYPE,
	_certificate			certificate.CERTIFICATE%TYPE,
	_cert_type				integer,
	_linter					linter_type
);

DROP TABLE lint_summary;

DROP TABLE lint_cert_issue;

DROP TABLE lint_issue;

DROP TABLE linter_version;

DROP TYPE linter_type;

DROP TABLE ct_log_entry;

DROP TABLE ct_log_operator;

DROP TABLE ct_log;

DROP TABLE ocsp_responder;

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
