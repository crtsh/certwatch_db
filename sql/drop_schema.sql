DROP VIEW certificate_lifecycle;

DROP VIEW certificate_identity;


DROP FUNCTION test_websites(
	dir						text,
	sort					integer,
	trustedBy				text
);

DROP FUNCTION revoked_intermediates(
);

DROP FUNCTION ocsp_response(
	caID					ocsp_responder.CA_ID%TYPE,
	url						ocsp_responder.URL%TYPE,
	request					text,
	type					text
);

DROP FUNCTION ocsp_responders(
	dir						text,
	sort					integer,
	url						text,
	trustedBy				text,
	trustedFor				text,
	trustedExclude			text,
	get						text,
	post					text,
	randomserial			text
);

DROP FUNCTION zlint_embedded(
	cert					bytea
);

DROP FUNCTION ocsp_randomserial_embedded(
	issuer_cert				bytea,
	ocsp_url				text
);

DROP FUNCTION ocsp_embedded(
	cert					bytea,
	issuer_cert				bytea
);

DROP FUNCTION mozilla_disclosures(
);

DROP FUNCTION microsoft_disclosures(
);

DROP FUNCTION disclosure_problems(
	certificateID		ccadb_certificate.CERTIFICATE_ID%TYPE,
	trustContextID		trust_context.ID%TYPE
);

DROP FUNCTION ccadb_disclosure_group2(
	trustContextID		trust_context.ID%TYPE,
	disclosureStatus	disclosure_status_type,
	anchor				text,
	description			text,
	bgColour			text
);

DROP FUNCTION ccadb_disclosure_group_summary(
	trustContextID		trust_context.ID%TYPE,
	disclosureStatus	disclosure_status_type,
	anchor				text,
	bgColour			text
);

DROP FUNCTION ccadb_disclosure_group(
	trustContextID		trust_context.ID%TYPE,
	disclosureStatus	disclosure_status_type,
	anchor				text,
	description			text,
	bgColour			text
);


DROP FUNCTION web_apis(
	name					text,
	paramNames				text[],
	paramValues				text[]
);

DROP FUNCTION serial_number_bitlength(
	serial_number			bytea
);

DROP FUNCTION process_new_entries(
);

DROP FUNCTION is_technically_constrained(
	cert_data				bytea
);

DROP FUNCTION import_chain_cert(
	ca_cert_data			bytea,
	issuer_ca_id			certificate.ISSUER_CA_ID%TYPE
);

DROP FUNCTION import_cert(
	cert_data				bytea
);

DROP FUNCTION html_escape(
	in_string				text
);

DROP FUNCTION getsth_update(
);

DROP FUNCTION get_parameter(
	parameter				text,
	paramNames				text[],
	paramValues				text[]
);

DROP FUNCTION get_ca_name_attribute(
	ca_id_					ca.ID%TYPE,
	attribute_type			text
);

DROP FUNCTION generate_add_chain_body(
	cert_data				certificate.CERTIFICATE%TYPE,
	only_one_chain			boolean
);

DROP FUNCTION enumerate_chains(
	cert_id					certificate.ID%TYPE,
	must_be_time_valid		boolean,
	trust_ctx_id			trust_context.ID%TYPE,
	trust_purp_id			trust_purpose.ID%TYPE,
	only_one_chain			boolean,
	max_ca_repeats			integer,
	certchain_so_far		bigint[],
	cachain_so_far			integer[]
);

DROP FUNCTION download_cert(
	cert_id					text
);

DROP FUNCTION determine_ca_trust_purposes(
	max_iterations			integer
);

DROP FUNCTION crl_update(
	_ca_id					crl.CA_ID%TYPE,
	_distribution_point_url	crl.DISTRIBUTION_POINT_URL%TYPE,
	_this_update			crl.THIS_UPDATE%TYPE,
	_next_update			crl.NEXT_UPDATE%TYPE,
	_last_checked			crl.LAST_CHECKED%TYPE,
	_error_message			crl.ERROR_MESSAGE%TYPE,
	_crl_sha256				crl.CRL_SHA256%TYPE,
	_crl_size				crl.CRL_SIZE%TYPE
);

DROP FUNCTION ci_error_message(
);


DROP TABLE cached_response;

DROP TABLE mozilla_root_hashes;

DROP TABLE mozilla_cert_validation_success;

DROP TABLE mozilla_cert_validation_success_import;

DROP TABLE mozilla_onecrl;

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

DROP TABLE accepted_roots;

DROP TABLE ct_log_entry;

DROP TABLE ct_log_operator;

DROP TABLE ct_log;

DROP TABLE ocsp_responder;

DROP TABLE crl_revoked;

DROP TABLE crl;

DROP TABLE ca_certificate;

DROP TABLE invalid_certificate;

DROP VIEW certificate_and_identities;

DROP TRIGGER cert_counter;

DROP FUNCTION update_expirations(
	ca_id					ca.ID%TYPE,
	max_interval			interval
);

DROP FUNCTION cert_counter(
);

DROP TABLE certificate;

DROP FUNCTION identities(
	cert					bytea,
	is_subject				boolean
);

DROP TABLE ca;

DROP TEXT SEARCH CONFIGURATION certwatch;
 
DROP TEXT SEARCH DICTIONARY certwatch;


-- As the "postgres" user.

DROP EXTENSION libzlintpq;

DROP EXTENSION pgcrypto;
