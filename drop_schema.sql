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

DROP FUNCTION extract_cert_names(
	cert_id					certificate.ID%TYPE,
	issuerca_id				ca.ID%TYPE
);

DROP FUNCTION download_cert(
	cert_id					certificate.ID%TYPE
);

DROP FUNCTION cablint(
	cert_data				bytea
);


DROP TABLE ct_log_entry;

DROP TABLE ct_log;

DROP TABLE ca_certificate;

DROP TABLE certificate_identity;

DROP TYPE name_type;

DROP TABLE certificate;

DROP TABLE ca;
