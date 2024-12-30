-- Run libx509pq/create_functions.sql first.


-- As the "postgres" user.

CREATE DATABASE certwatch ENCODING=UTF8;

\connect certwatch postgres

CREATE ROLE certwatch WITH LOGIN;

GRANT USAGE, CREATE ON SCHEMA public TO certwatch;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT UPDATE, INSERT, SELECT, DELETE ON TABLES TO certwatch;

CREATE ROLE guest WITH LOGIN PASSWORD 'guest';

CREATE ROLE httpd WITH LOGIN PASSWORD 'httpd';


CREATE EXTENSION pgcrypto;


CREATE EXTENSION libzlintpq;


\connect certwatch certwatch

CREATE TABLE ca (
	ID						serial,
	NUM_ISSUED				bigint[],
	NUM_EXPIRED				bigint[],
	LAST_CERTIFICATE_ID		bigint,
	LAST_NOT_AFTER			timestamp,
	NEXT_NOT_AFTER			timestamp,
	LINTING_APPLIES			boolean		DEFAULT TRUE						NOT NULL,
	NAME					text											NOT NULL,
	PUBLIC_KEY				bytea											NOT NULL,
	CONSTRAINT ca_pk
		PRIMARY KEY (ID)
);

CREATE INDEX ca_last_cert
	ON ca (LAST_CERTIFICATE_ID DESC NULLS LAST)
	WHERE LAST_CERTIFICATE_ID IS NOT NULL;

CREATE INDEX ca_next_not_after
	ON ca (NEXT_NOT_AFTER)
	WHERE NEXT_NOT_AFTER IS NOT NULL;

CREATE INDEX ca_linting_applies
	ON ca (LINTING_APPLIES, ID);

CREATE INDEX ca_name
	ON ca (lower(NAME) text_pattern_ops);

CREATE INDEX ca_name_reverse
	ON ca (reverse(lower(NAME)) text_pattern_ops);

CREATE UNIQUE INDEX ca_uniq
	ON ca (NAME text_pattern_ops, PUBLIC_KEY);

CREATE INDEX ca_spki_sha256
	ON ca (digest(PUBLIC_KEY, 'sha256'));

INSERT INTO ca ( ID, NAME, PUBLIC_KEY ) VALUES ( -1, 'Issuer Not Found', E'\\x00' );


CREATE TABLE certificate (
	ID				bigserial	NOT NULL,
	ISSUER_CA_ID	integer		NOT NULL,
	CERTIFICATE		bytea		NOT NULL,
	CONSTRAINT c_ica_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
) PARTITION BY RANGE (coalesce(x509_notAfter(CERTIFICATE), 'infinity'::timestamp));

CREATE TABLE certificate_2013andbefore PARTITION OF certificate
	FOR VALUES FROM (MINVALUE) TO ('2014-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2014 PARTITION OF certificate
	FOR VALUES FROM ('2014-01-01T00:00:00'::timestamp) TO ('2015-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2015 PARTITION OF certificate
	FOR VALUES FROM ('2015-01-01T00:00:00'::timestamp) TO ('2016-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2016 PARTITION OF certificate
	FOR VALUES FROM ('2016-01-01T00:00:00'::timestamp) TO ('2017-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2017 PARTITION OF certificate
	FOR VALUES FROM ('2017-01-01T00:00:00'::timestamp) TO ('2018-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2018 PARTITION OF certificate
	FOR VALUES FROM ('2018-01-01T00:00:00'::timestamp) TO ('2019-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2019 PARTITION OF certificate
	FOR VALUES FROM ('2019-01-01T00:00:00'::timestamp) TO ('2020-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2020 PARTITION OF certificate
	FOR VALUES FROM ('2020-01-01T00:00:00'::timestamp) TO ('2021-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2021 PARTITION OF certificate
	FOR VALUES FROM ('2021-01-01T00:00:00'::timestamp) TO ('2022-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2022 PARTITION OF certificate
	FOR VALUES FROM ('2022-01-01T00:00:00'::timestamp) TO ('2023-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2023 PARTITION OF certificate
	FOR VALUES FROM ('2023-01-01T00:00:00'::timestamp) TO ('2024-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2024 PARTITION OF certificate
	FOR VALUES FROM ('2024-01-01T00:00:00'::timestamp) TO ('2025-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2025 PARTITION OF certificate
	FOR VALUES FROM ('2025-01-01T00:00:00'::timestamp) TO ('2026-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2026 PARTITION OF certificate
	FOR VALUES FROM ('2026-01-01T00:00:00'::timestamp) TO ('2027-01-01T00:00:00'::timestamp);

CREATE TABLE certificate_2027andbeyond PARTITION OF certificate
	FOR VALUES FROM ('2027-01-01T00:00:00'::timestamp) TO (MAXVALUE);

CREATE INDEX c_id ON certificate (ID);

CREATE INDEX c_sha1 ON certificate (digest(CERTIFICATE, 'sha1'));

CREATE INDEX c_sha256 ON certificate (digest(CERTIFICATE, 'sha256'));

CREATE INDEX c_serial ON certificate (x509_serialNumber(CERTIFICATE));

CREATE INDEX c_spki_sha1 ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha1'));

CREATE INDEX c_spki_sha256 ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha256'));

CREATE INDEX c_pubkey_md5 ON certificate (x509_publicKeyMD5(CERTIFICATE));

CREATE INDEX c_ica_notbefore ON certificate (ISSUER_CA_ID, x509_notBefore(CERTIFICATE));

CREATE INDEX c_ica_notafter ON certificate (ISSUER_CA_ID, coalesce(x509_notAfter(CERTIFICATE), 'infinity'::timestamp));

CREATE INDEX c_ica_canissue ON certificate (ISSUER_CA_ID) WHERE x509_canIssueCerts(CERTIFICATE);

CREATE INDEX c_subject_sha1 ON certificate (digest(x509_name(CERTIFICATE), 'sha1'));

CREATE INDEX c_ski ON certificate (x509_subjectKeyIdentifier(CERTIFICATE));


CREATE TEXT SEARCH DICTIONARY certwatch (
    TEMPLATE = pg_catalog.simple
);

CREATE TEXT SEARCH CONFIGURATION certwatch (
    COPY = pg_catalog.simple
);

\i fnc/safe_convert_utf8.fnc
\i fnc/identities.fnc

CREATE INDEX c_identities ON certificate USING GIN (identities(CERTIFICATE));


\i fnc/cert_counter.trg

CREATE TRIGGER cert_counter
	AFTER UPDATE OR DELETE ON certificate
	FOR EACH ROW
	EXECUTE PROCEDURE cert_counter();


CREATE VIEW certificate_and_identities AS
SELECT c.ID CERTIFICATE_ID, c.CERTIFICATE, ci.NAME_TYPE, ci.NAME_VALUE, c.ISSUER_CA_ID
	FROM certificate c
			LEFT JOIN LATERAL (
				SELECT encode(RAW_VALUE, 'escape') AS NAME_VALUE,
						ATTRIBUTE_OID AS NAME_TYPE
					FROM x509_nameAttributes_raw(c.CERTIFICATE)
				UNION
				SELECT encode(RAW_VALUE, 'escape') AS NAME_VALUE,
						'san:' || CASE TYPE_NUM
							WHEN 0 THEN 'otherName'
							WHEN 1 THEN 'rfc822Name'
							WHEN 2 THEN 'dNSName'
							WHEN 3 THEN 'x400Address'
							WHEN 4 THEN 'directoryName'
							WHEN 5 THEN 'ediPartyName'
							WHEN 6 THEN 'uniformResourceIdentifier'
							WHEN 7 THEN 'iPAddress'
							WHEN 8 THEN 'registeredID'
						END AS NAME_TYPE
					FROM x509_altNames_raw(c.CERTIFICATE)
			) ci ON TRUE;


CREATE TABLE invalid_certificate (
	ID						serial,
	CERTIFICATE_ID			bigint,
	PROBLEMS				text,
	CERTIFICATE_AS_LOGGED	bytea,
	CONSTRAINT ic_pk
		PRIMARY KEY (ID)
);


CREATE TABLE ca_certificate (
	CERTIFICATE_ID			bigint,
	CA_ID					integer,
	CONSTRAINT cac_pk
		PRIMARY KEY (CERTIFICATE_ID),
	CONSTRAINT cac_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX cac_ca_c
	ON ca_certificate (CA_ID, CERTIFICATE_ID);


CREATE TABLE crl (
	CA_ID					integer,
	THIS_UPDATE				timestamp,
	NEXT_UPDATE				timestamp,
	LAST_CHECKED			timestamp,
	NEXT_CHECK_DUE			timestamp,
	DISTRIBUTION_POINT_URL	text,
	ERROR_MESSAGE			text,
	CRL_SHA256				bytea,
	CRL_SIZE				integer,
	IS_ACTIVE				boolean,
	FIRST_CERTIFICATE_ID	bigint,
	CONSTRAINT crl_pk
		PRIMARY KEY (CA_ID, DISTRIBUTION_POINT_URL),
	CONSTRAINT crl_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX crl_ia_lc
	ON crl (IS_ACTIVE, NEXT_CHECK_DUE, DISTRIBUTION_POINT_URL);

CREATE INDEX crl_sz
	ON crl (CRL_SIZE);


CREATE TABLE crl_revoked (
	CA_ID					integer,
	SERIAL_NUMBER			bytea,
	REASON_CODE				smallint,
	REVOCATION_DATE			timestamp,
	LAST_SEEN_CHECK_DATE	timestamp,
	CONSTRAINT crlr_pk
		PRIMARY KEY (CA_ID, SERIAL_NUMBER),
	CONSTRAINT crlr_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX crlr_ca_revdate
	ON crl_revoked (CA_ID, REVOCATION_DATE);


CREATE TABLE ocsp_responder (
	CA_ID						integer,
	NEXT_CHECKS_DUE				timestamp,
	LAST_CHECKED				timestamp,
	URL							text,
	IGNORE_OTHER_URLS			boolean		NOT NULL	DEFAULT FALSE,
	FIRST_CERTIFICATE_ID		bigint,
	TESTED_CERTIFICATE_ID		bigint,
	GET_RESULT					text,
	GET_DUMP					bytea,
	GET_DURATION				bigint,
	POST_RESULT					text,
	POST_DUMP					bytea,
	POST_DURATION				bigint,
	GET_RANDOM_SERIAL_RESULT	text,
	GET_RANDOM_SERIAL_DUMP		bytea,
	GET_RANDOM_SERIAL_DURATION	bigint,
	POST_RANDOM_SERIAL_RESULT	text,
	POST_RANDOM_SERIAL_DUMP		bytea,
	POST_RANDOM_SERIAL_DURATION	bigint,
	FORWARD_SLASHES_RESULT		text,
	FORWARD_SLASHES_DUMP		bytea,
	FORWARD_SLASHES_DURATION	bigint,
	SHA256_CERTID_RESULT		text,
	SHA256_CERTID_DUMP			bytea,
	SHA256_CERTID_DURATION		bigint,
	RAW_PLUSES_RESULT			text,
	RAW_PLUSES_DUMP				bytea,
	RAW_PLUSES_DURATION			bigint,
	CONSTRAINT or_pk
		PRIMARY KEY (CA_ID, URL),
	CONSTRAINT or_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX or_iou
	ON ocsp_responder ( CA_ID, IGNORE_OTHER_URLS )
	WHERE IGNORE_OTHER_URLS;


CREATE TABLE ca_issuer (
	CA_ID					integer,
	NEXT_CHECK_DUE			timestamp,
	LAST_CHECKED			timestamp,
	URL						text,
	RESULT					text,
	CA_CERTIFICATE_IDS		bigint[],
	FIRST_CERTIFICATE_ID	bigint,
	IS_ACTIVE				boolean,
	CONTENT_TYPE			text,
	CONSTRAINT cais_pk
		PRIMARY KEY (CA_ID, URL),
	CONSTRAINT cais_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);


CREATE TYPE ct_log_type AS ENUM (
	'rfc6962', 'static'
);

CREATE TABLE ct_log (
	ID							integer,
	OPERATOR					text,
	TYPE						ct_log_type	DEFAULT 'rfc6962'	NOT NULL,
	URL							text,
	SUBMISSION_URL				text,
	NAME						text,
	PUBLIC_KEY					bytea,
	IS_ACTIVE					boolean,
	LATEST_UPDATE				timestamp,
	LATEST_STH_TIMESTAMP		timestamp,
	MMD_IN_SECONDS				integer,
	TREE_SIZE					bigint,
	BATCH_SIZE					integer,
	CHUNK_SIZE					integer,
	REQUESTS_THROTTLE			text,
	REQUESTS_CONCURRENT			integer,
	GOOGLE_UPTIME				text,
	CHROME_VERSION_ADDED		integer,
	CHROME_INCLUSION_STATUS		text,
	CHROME_ISSUE_NUMBER			integer,
	CHROME_FINAL_TREE_SIZE		integer,
	CHROME_DISQUALIFIED_AT		timestamp,
	APPLE_INCLUSION_STATUS		text,
	APPLE_LAST_STATUS_CHANGE	timestamp,
	MICROSOFT_INCLUSION_STATUS	text,
	MOZILLA_INCLUSION_STATUS	text,
	MOZILLA_LAST_STATUS_CHANGE	timestamp,
	CONSTRAINT ctl_pk
		PRIMARY KEY (ID),
	CONSTRAINT ctl_url_unq
		UNIQUE (URL),
	CONSTRAINT ctl_reqconcurrent_chk
		CHECK (REQUESTS_CONCURRENT > 1)
);

CREATE UNIQUE INDEX ctl_sha256_pubkey
	ON ct_log (digest(PUBLIC_KEY, 'sha256'));

CREATE TABLE ct_log_operator (
	OPERATOR				text,
	DISPLAY_STRING			text,
	CONSTRAINT ctlo_pk
		PRIMARY KEY (OPERATOR)
);

CREATE TABLE ct_log_entry (
	CERTIFICATE_ID	bigint		NOT NULL,
	ENTRY_ID		bigint		NOT NULL,
	ENTRY_TIMESTAMP	timestamp	NOT NULL,
	CT_LOG_ID		integer		NOT NULL,
	CONSTRAINT ctle_ctl_fk
		FOREIGN KEY (CT_LOG_ID)
		REFERENCES ct_log(ID)
) PARTITION BY RANGE (ENTRY_TIMESTAMP);

CREATE TABLE ct_log_entry_2013 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2013-01-01T00:00:00'::timestamp) TO ('2014-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2014 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2014-01-01T00:00:00'::timestamp) TO ('2015-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2015 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2015-01-01T00:00:00'::timestamp) TO ('2016-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2016 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2016-01-01T00:00:00'::timestamp) TO ('2017-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2017 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2017-01-01T00:00:00'::timestamp) TO ('2018-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2018 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2018-01-01T00:00:00'::timestamp) TO ('2019-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2019 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2019-01-01T00:00:00'::timestamp) TO ('2020-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2020 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2020-01-01T00:00:00'::timestamp) TO ('2021-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2021 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2021-01-01T00:00:00'::timestamp) TO ('2022-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2022 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2022-01-01T00:00:00'::timestamp) TO ('2023-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2023 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2023-01-01T00:00:00'::timestamp) TO ('2024-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2024 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2024-01-01T00:00:00'::timestamp) TO ('2025-01-01T00:00:00'::timestamp);

CREATE TABLE ct_log_entry_2025 PARTITION OF ct_log_entry
	FOR VALUES FROM ('2025-01-01T00:00:00'::timestamp) TO ('2026-01-01T00:00:00'::timestamp);


CREATE INDEX ctle_c ON ct_log_entry (CERTIFICATE_ID);

CREATE INDEX ctle_e ON ct_log_entry (ENTRY_ID);

CREATE INDEX ctle_t ON ct_log_entry (ENTRY_TIMESTAMP);

CREATE INDEX ctle_le ON ct_log_entry (CT_LOG_ID, ENTRY_ID DESC);


CREATE TABLE accepted_roots (
	CT_LOG_ID			integer,
	CERTIFICATE_ID		bigint,
	CONSTRAINT ar_pk
		PRIMARY KEY (CT_LOG_ID, CERTIFICATE_ID)
);

CREATE INDEX ar_c ON accepted_roots (CERTIFICATE_ID);


CREATE TYPE linter_type AS ENUM (
	'cablint', 'x509lint', 'zlint'
);

CREATE TABLE linter_version (
	ID					integer,
	MIN_CERTIFICATE_ID	bigint,
	MAX_CERTIFICATE_ID	bigint,
	DEPLOYED_AT			timestamp,
	LINTER				linter_type,
	VERSION_STRING		text,
	GIT_COMMIT			bytea,
	CONSTRAINT lv_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX lv_li_da
	ON linter_version (LINTER, DEPLOYED_AT);


CREATE TABLE lint_issue (
	ID				serial,
	LINTER			linter_type,
	SEVERITY		text,
	ISSUE_TEXT		text,
	CONSTRAINT li_pk
		PRIMARY KEY (ID),
	CONSTRAINT li_li_se_it_unq
		UNIQUE (LINTER, SEVERITY, ISSUE_TEXT)
);

INSERT INTO lint_issue (ID, ISSUE_TEXT) VALUES (-1, 'Daily Certificate Count');

CREATE TABLE lint_cert_issue (
	CERTIFICATE_ID		bigint,
	LINT_ISSUE_ID		integer,
	ISSUER_CA_ID		integer,
	NOT_BEFORE_DATE		date,
	CONSTRAINT lci_pk
		PRIMARY KEY (ISSUER_CA_ID, LINT_ISSUE_ID, NOT_BEFORE_DATE, CERTIFICATE_ID),
	CONSTRAINT lci_li_fk
		FOREIGN KEY (LINT_ISSUE_ID)
		REFERENCES lint_issue(ID),
	CONSTRAINT lci_ca_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX lci_c
	ON lint_cert_issue (CERTIFICATE_ID);

CREATE INDEX lci_li_nbd
	ON lint_cert_issue (LINT_ISSUE_ID, NOT_BEFORE_DATE);

CREATE TABLE lint_summary (
	LINT_ISSUE_ID	integer,
	ISSUER_CA_ID	integer,
	NOT_BEFORE_DATE	date,
	NO_OF_CERTS		integer,
	CONSTRAINT ls_pk
		PRIMARY KEY (LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE),
	CONSTRAINT ls_li_fk
		FOREIGN KEY (LINT_ISSUE_ID)
		REFERENCES lint_issue(ID),
	CONSTRAINT ls_ca_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

\i linting/lint_new_cert.fnc
\i linting/lint_certificate.fnc
\i linting/lint_tbscertificate.fnc
\i linting/lint_summarizer.trg

CREATE TRIGGER lint_summarizer
	BEFORE INSERT OR UPDATE OR DELETE ON lint_cert_issue
	FOR EACH ROW
	EXECUTE PROCEDURE lint_summarizer();


CREATE TABLE trust_context (
	ID				integer,
	DISPLAY_ORDER	integer,
	CTX				text		NOT NULL,
	URL				text,
	VERSION			text,
	VERSION_URL		text,
	CONSTRAINT tc_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX tc_ctx_uniq
	ON trust_context (CTX text_pattern_ops);

INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 1, 'Microsoft', 'https://aka.ms/rootcert', 2 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 5, 'Mozilla', 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/', 3 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 6, 'Chrome', 'https://www.chromium.org/Home/chromium-security/root-ca-policy', 4 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 9, 'Adobe AATL', 'https://helpx.adobe.com/acrobat/kb/approved-trust-list2.html', 11 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 10, 'Adobe CDS', 'https://helpx.adobe.com/acrobat/kb/certified-document-services.html', 12 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 12, 'Apple', 'https://www.apple.com/certificateauthority/ca_program.html', 1 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 13, 'Cisco', 'https://www.cisco.com/security/pki/trs/ios.p7b', 8 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 17, 'Android', 'https://android.googlesource.com/platform/system/ca-certificates/', 5 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 23, 'Java', 'http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html', 7 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 24, 'Adobe EUTL', 'https://blogs.adobe.com/documentcloud/eu-trusted-list-now-available-in-adobe-acrobat/', 10 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 25, '360 Browser', 'https://caprogram.360.cn/#trust', 0 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 26, 'Gmail', 'https://support.google.com/a/answer/7448393?hl=en', 6 );
INSERT INTO trust_context ( ID, CTX, URL, DISPLAY_ORDER ) VALUES ( 27, 'EUTL QWAC', 'https://eidas.ec.europa.eu/efda/tl-browser/', 9 );

CREATE TABLE trust_purpose (
	ID					integer,
	DISPLAY_ORDER		integer,
	PURPOSE				text,
	PURPOSE_OID			text,
	CONSTRAINT tp_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX tp_purpose_uniq
	ON trust_purpose (PURPOSE text_pattern_ops, PURPOSE_OID text_pattern_ops);

INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 1, 'Server Authentication', '1.3.6.1.5.5.7.3.1', 2 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 2, 'Client Authentication', '1.3.6.1.5.5.7.3.2', 10 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 3, 'Secure Email', '1.3.6.1.5.5.7.3.4', 11 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 4, 'Code Signing', '1.3.6.1.5.5.7.3.3', 20 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 5, 'Time Stamping', '1.3.6.1.5.5.7.3.8', 22 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 6, 'OCSP Signing', '1.3.6.1.5.5.7.3.9', 30 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 7, 'Document Signing', '1.3.6.1.4.1.311.10.3.12', 31 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 8, 'Encrypting File System', '1.3.6.1.4.1.311.10.3.4', 32 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 9, 'IP security end system', '1.3.6.1.5.5.7.3.5', 40 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 10, 'IP security IKE intermediate', '1.3.6.1.5.5.8.2.2', 41 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 11, 'IP security tunnel termination', '1.3.6.1.5.5.7.3.6', 42 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 12, 'IP security user', '1.3.6.1.5.5.7.3.7', 43 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 14, 'Adobe Authentic Document', '1.2.840.113583.1.1.5', 44 );

INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 50, 'Kernel Mode Code Signing', '1.3.6.1.5.5.7.3.3', 21 );

INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 100, 'EV Server Authentication', '1.2.250.1.177.1.18.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 101, 'EV Server Authentication', '1.2.276.0.44.1.1.1.4', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 102, 'EV Server Authentication', '1.2.392.200091.100.721.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 103, 'EV Server Authentication', '1.2.40.0.17.1.22', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 104, 'EV Server Authentication', '1.2.616.1.113527.2.5.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 105, 'EV Server Authentication', '1.3.6.1.4.1.14370.1.6', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 106, 'EV Server Authentication', '1.3.6.1.4.1.14777.6.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 107, 'EV Server Authentication', '1.3.6.1.4.1.14777.6.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 108, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.14.2.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 109, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.8.12.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 110, 'EV Server Authentication', '1.3.6.1.4.1.22234.2.5.2.3.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 111, 'EV Server Authentication', '1.3.6.1.4.1.23223.1.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 112, 'EV Server Authentication', '1.3.6.1.4.1.29836.1.10', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 113, 'EV Server Authentication', '1.3.6.1.4.1.34697.2.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 114, 'EV Server Authentication', '1.3.6.1.4.1.34697.2.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 115, 'EV Server Authentication', '1.3.6.1.4.1.34697.2.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 116, 'EV Server Authentication', '1.3.6.1.4.1.34697.2.4', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 117, 'EV Server Authentication', '1.3.6.1.4.1.4146.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 118, 'EV Server Authentication', '1.3.6.1.4.1.4788.2.202.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 119, 'EV Server Authentication', '1.3.6.1.4.1.5237.1.1.6', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 120, 'EV Server Authentication', '1.3.6.1.4.1.6334.1.100.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 121, 'EV Server Authentication', '1.3.6.1.4.1.6449.1.2.1.5.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 122, 'EV Server Authentication', '1.3.6.1.4.1.782.1.2.1.8.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 123, 'EV Server Authentication', '1.3.6.1.4.1.7879.13.24.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 124, 'EV Server Authentication', '1.3.6.1.4.1.8024.0.2.100.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 125, 'EV Server Authentication', '2.16.578.1.26.1.3.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 126, 'EV Server Authentication', '2.16.756.1.89.1.2.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 127, 'EV Server Authentication', '2.16.792.3.0.3.1.1.5', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 128, 'EV Server Authentication', '2.16.840.1.113733.1.7.23.6', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 129, 'EV Server Authentication', '2.16.840.1.113733.1.7.48.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 130, 'EV Server Authentication', '2.16.840.1.114028.10.1.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 131, 'EV Server Authentication', '2.16.840.1.114171.500.9', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 132, 'EV Server Authentication', '2.16.840.1.114404.1.1.2.4.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 133, 'EV Server Authentication', '2.16.840.1.114412.2.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 134, 'EV Server Authentication', '2.16.840.1.114413.1.7.23.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 135, 'EV Server Authentication', '2.16.840.1.114414.1.7.23.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 136, 'EV Server Authentication', '2.16.840.1.114414.1.7.24.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 137, 'EV Server Authentication', '2.16.840.1.114414.1.7.24.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 138, 'EV Server Authentication', '2.16.886.3.1.6.5', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 139, 'EV Server Authentication', '1.3.6.1.4.1.40869.1.1.22.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 140, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.14.2.2.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 141, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.8.12.2.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 142, 'EV Server Authentication', '2.16.156.112554.3', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 143, 'EV Server Authentication', '1.3.6.1.4.1.36305.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 144, 'EV Server Authentication', '2.16.756.1.83.2.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 145, 'EV Server Authentication', '1.3.6.1.4.1.23223.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 146, 'EV Server Authentication', '2.16.840.1.114412.1.3.0.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 147, 'EV Server Authentication', '2.16.756.1.83.21.0', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 148, 'EV Server Authentication', '2.16.792.3.0.4.1.1.4', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 149, 'EV Server Authentication', '1.3.6.1.4.1.13177.10.1.3.10', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 150, 'EV Server Authentication', '1.2.250.1.177.1.18.2.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 151, 'EV Server Authentication', '1.2.392.200091.100.921.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 152, 'EV Server Authentication', '1.3.159.1.17.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 153, 'EV Server Authentication', '0.4.0.2042.1.4', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 154, 'EV Server Authentication', '0.4.0.2042.1.5', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 155, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.2.12', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 156, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.2.22', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 157, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.5.12', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 158, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.5.22', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 159, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.6.12', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 160, 'EV Server Authentication', '1.3.6.1.4.1.18332.55.1.1.6.22', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 161, 'EV Server Authentication', '2.16.528.1.1003.1.2.7', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 162, 'EV Server Authentication', '1.3.171.1.1.10.5.2', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 163, 'EV Server Authentication', '1.2.752.146.3.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 164, 'EV Server Authentication', '1.2.156.112559.1.1.6.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 165, 'EV Server Authentication', '1.2.156.112559.1.1.7.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 166, 'EV Server Authentication', '2.16.756.5.14.7.4.8', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 167, 'EV Server Authentication', '2.23.140.1.1', 1);
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 168, 'EV Server Authentication', '1.3.6.1.4.1.22234.3.5.3.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 169, 'EV Server Authentication', '1.3.6.1.4.1.38064.1.1.1.0', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 170, 'EV Server Authentication', '1.3.6.1.4.1.22234.2.14.3.11', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 171, 'EV Server Authentication', '1.3.6.1.4.1.22234.3.5.3.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 172, 'EV Server Authentication', '1.2.156.112570.1.1.3.0', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 173, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.8.12.1.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 174, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.14.2.1.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 175, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.16.3.5.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 176, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.16.3.5.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 177, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.16.3.6.1.3.2.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 178, 'EV Server Authentication', '1.3.6.1.4.1.17326.10.16.3.6.1.3.2.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 179, 'EV Server Authentication', '1.3.6.1.4.1.15096.1.3.1.51.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 180, 'EV Server Authentication', '1.3.6.1.4.1.15096.1.3.1.51.4', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 181, 'EV Server Authentication', '1.3.6.1.4.1.15096.1.3.2.5.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 182, 'EV Server Authentication', '1.3.6.1.4.1.15096.1.3.2.51.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 183, 'EV Server Authentication', '1.2.156.112570.1.1.3', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 184, 'EV Server Authentication', '1.3.6.1.4.1.23459.100.9', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 185, 'EV Server Authentication', '2.23.140.1.2.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 186, 'EV Server Authentication', '2.23.140.1.3', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 187, 'EV Server Authentication', '1.3.6.1.4.1.311.94.1.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 188, 'EV Server Authentication', '1.3.6.1.4.1.311.60.1.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 189, 'EV Server Authentication', '1.3.171.1.1.1.10.5', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 190, 'EV Server Authentication', '1.3.171.1.1.10.5.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 191, 'EV Server Authentication', '1.3.171.1.1.1.10.3', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 192, 'EV Server Authentication', '2.16.840.1.113839.0.6.9', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 193, 'EV Server Authentication', '2.16.756.1.17.3.22.32', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 194, 'EV Server Authentication', '2.16.756.1.17.3.22.34', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 195, 'EV Server Authentication', '2.16.756.1.17.3.22.51', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 196, 'EV Server Authentication', '1.3.171.1.1.1.10.8', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 197, 'EV Server Authentication', '1.2.616.1.113527.2.5.1.7', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 198, 'EV Server Authentication', '1.3.6.1.4.1.4146.1.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 199, 'EV Server Authentication', '0.4.0.194112.1.4', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 200, 'EV Server Authentication', '1.3.6.1.4.1.23624.10.1.35.1.0', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 201, 'EV Server Authentication', '2.16.840.1.113839.0.6.14.1', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 202, 'EV Server Authentication', '1.3.6.1.4.1.38064.1.3.1.4', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 203, 'EV Server Authentication', '1.3.6.1.4.1.38064.1.3.3.2', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 204, 'EV Server Authentication', '1.3.6.1.4.1.26513.1.1.4', 1 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 205, 'EV Server Authentication', '1.3.6.1.4.1.26513.1.3.3', 1 );

INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 1000, 'Qualified Website Authentication', '0.4.0.194112.1.4', 0 );


CREATE TABLE applicable_purpose(
	TRUST_CONTEXT_ID	integer,
	PURPOSE				text,
	CONSTRAINT ap_pk
		PRIMARY KEY (TRUST_CONTEXT_ID, PURPOSE),
	CONSTRAINT ap_tc_fk
		FOREIGN KEY (TRUST_CONTEXT_ID)
		REFERENCES trust_context(ID)
);

INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Client Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Kernel Mode Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Document Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Encrypting File System' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'IP security end system' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'IP security IKE intermediate' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'IP security tunnel termination' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'IP security user' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'OCSP Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Time Stamping' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 6, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 6, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Document Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Adobe Authentic Document' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Time Stamping' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 10, 'Adobe Authentic Document' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Client Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Time Stamping' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 13, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 17, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 23, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 23, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Document Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Adobe Authentic Document' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Time Stamping' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 25, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 26, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 27, 'Qualified Website Authentication' );


CREATE TABLE root_trust_purpose(
	CERTIFICATE_ID		bigint,
	TRUST_CONTEXT_ID	integer,
	TRUST_PURPOSE_ID	integer,
	DISABLED_FROM		timestamp,
	NOTBEFORE_UNTIL		timestamp,
	CONSTRAINT rtp_pk
		PRIMARY KEY (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID),
	CONSTRAINT rtp_tc_fk
		FOREIGN KEY (TRUST_CONTEXT_ID)
		REFERENCES trust_context(ID),
	CONSTRAINT rtp_tp_fk
		FOREIGN KEY (TRUST_PURPOSE_ID)
		REFERENCES trust_purpose(ID)
);


CREATE TABLE ca_trust_purpose (
	CA_ID									integer,
	TRUST_CONTEXT_ID						integer,
	TRUST_PURPOSE_ID						integer,
	SHORTEST_CHAIN							integer,
	ITERATION_LAST_MODIFIED					integer,
	PATH_LEN_CONSTRAINT						integer,
	IS_TIME_VALID							boolean,
	ALL_CHAINS_TECHNICALLY_CONSTRAINED		boolean,
	ALL_CHAINS_REVOKED_IN_SALESFORCE		boolean,
	ALL_CHAINS_REVOKED_VIA_ONECRL			boolean,
	ALL_CHAINS_REVOKED_VIA_CRLSET			boolean,
	ALL_CHAINS_REVOKED_VIA_DISALLOWEDSTL	boolean,
	DISABLED_FROM							timestamp,
	NOTBEFORE_UNTIL							timestamp,
	CONSTRAINT ctp_pk
		PRIMARY KEY (CA_ID, TRUST_PURPOSE_ID, TRUST_CONTEXT_ID),
	CONSTRAINT ctp_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID),
	CONSTRAINT ctp_tc_fk
		FOREIGN KEY (TRUST_CONTEXT_ID)
		REFERENCES trust_context(ID),
	CONSTRAINT ctp_tp_fk
		FOREIGN KEY (TRUST_PURPOSE_ID)
		REFERENCES trust_purpose(ID)
);


CREATE TYPE disclosure_status_type AS ENUM (
	'DisclosureIncomplete',
	'DisclosedWithInconsistentAudit',
	'DisclosedWithInconsistentCPS',
	'Undisclosed',
	'AllSuitablePathsRevoked',
	'NoKnownSuitableTrustPath',
	'TechnicallyConstrained',
	'TechnicallyConstrainedOther',
	'Expired',
	'Revoked',
	'RevokedAndTechnicallyConstrained',
	'ParentRevoked',
	'ParentRevokedButNotAllParents',
	'ParentRevokedButInOneCRL',
	'RevokedButExpired',
	'RevokedAndShouldBeAddedToOneCRL',
	'RevokedViaOneCRL',
	'RevokedViaOneCRLButExpired',
	'RevokedViaOneCRLButTechnicallyConstrained',
	'RevokedViaOneCRLButNotNeeded',
	'Disclosed',
	'DisclosedButExpired',
	'DisclosedButNoKnownSuitableTrustPath',
	'DisclosedButInOneCRL',
	'DisclosedButRemovedFromCRL',
	'DisclosedButConstrained',
	'DisclosedWithErrors',
	'DisclosedButInCRL'
);

CREATE TABLE ccadb_certificate(
	CCADB_RECORD_ID					text,
	CERTIFICATE_ID					bigint,
	PARENT_CERTIFICATE_ID			bigint,
	INCLUDED_CERTIFICATE_ID			bigint,
	INCLUDED_CERTIFICATE_OWNER		text,
	CA_OWNER						text,
	CERT_NAME						text,
	PARENT_CERT_NAME				text,
	CERT_RECORD_TYPE				text,
	REVOCATION_STATUS				text,
	CERT_SHA256						bytea,
	AUDITS_SAME_AS_PARENT			boolean,
	AUDITOR							text,
	STANDARD_AUDIT_URL				text,
	STANDARD_AUDIT_TYPE				text,
	STANDARD_AUDIT_DATE				date,
	STANDARD_AUDIT_START			date,
	STANDARD_AUDIT_END				date,
	NETSEC_AUDIT_URL				text,
	NETSEC_AUDIT_TYPE				text,
	NETSEC_AUDIT_DATE				text,
	NETSEC_AUDIT_START				text,
	NETSEC_AUDIT_END				text,
	BRSSL_AUDIT_URL					text,
	BRSSL_AUDIT_TYPE				text,
	BRSSL_AUDIT_DATE				date,
	BRSSL_AUDIT_START				date,
	BRSSL_AUDIT_END					date,
	EVSSL_AUDIT_URL					text,
	EVSSL_AUDIT_TYPE				text,
	EVSSL_AUDIT_DATE				date,
	EVSSL_AUDIT_START				date,
	EVSSL_AUDIT_END					date,
	CODE_AUDIT_URL					text,
	CODE_AUDIT_TYPE					text,
	CODE_AUDIT_DATE					date,
	CODE_AUDIT_START				date,
	CODE_AUDIT_END					date,
	SMIME_AUDIT_URL					text,
	SMIME_AUDIT_TYPE				text,
	SMIME_AUDIT_DATE				text,
	SMIME_AUDIT_START				text,
	SMIME_AUDIT_END					text,
	CP_SAME_AS_PARENT				boolean,
	CP_URL							text,
	CP_LAST_UPDATED					text,
	CPS_SAME_AS_PARENT				boolean,
	CPS_URL							text,
	CPS_LAST_UPDATED				text,
	CP_CPS_SAME_AS_PARENT			boolean,
	CP_CPS_URL						text,
	CP_CPS_LAST_UPDATED				text,
	TEST_WEBSITE_VALID				text,
	TEST_WEBSITE_EXPIRED			text,
	TEST_WEBSITE_REVOKED			text,
	IS_TECHNICALLY_CONSTRAINED		text,
	MOZILLA_STATUS					text,
	MICROSOFT_STATUS				text,
	CHROME_STATUS					text,
	DERIVED_TRUST_BITS				text,
	STATUS_OF_ROOT_CERT				text,
	ISSUER_CN						text,
	ISSUER_O						text,
	SUBJECT_CN						text,
	SUBJECT_O						text,
	MOZILLA_DISCLOSURE_STATUS		disclosure_status_type,
	MICROSOFT_DISCLOSURE_STATUS		disclosure_status_type,
	APPLE_DISCLOSURE_STATUS			disclosure_status_type,
	CHROME_DISCLOSURE_STATUS		disclosure_status_type,
	LAST_MOZILLA_DISCLOSURE_STATUS_CHANGE	timestamp,
	LAST_MICROSOFT_DISCLOSURE_STATUS_CHANGE	timestamp,
	LAST_APPLE_DISCLOSURE_STATUS_CHANGE		timestamp,
	LAST_CHROME_DISCLOSURE_STATUS_CHANGE	timestamp,
	PARENT_CCADB_RECORD_ID			text,
	PARENT_CERT_SHA256				text,
	TEST_WEBSITE_VALID_STATUS		text,
	TEST_WEBSITE_EXPIRED_STATUS		text,
	TEST_WEBSITE_REVOKED_STATUS		text,
	TEST_WEBSITE_VALID_CERTIFICATE_ID	bigint,
	TEST_WEBSITE_EXPIRED_CERTIFICATE_ID	bigint,
	TEST_WEBSITE_REVOKED_CERTIFICATE_ID	bigint,
	TEST_WEBSITES_CHECKED			boolean,
	SUBORDINATE_CA_OWNER			text,
	FULL_CRL_URL					text,
	JSON_ARRAY_OF_CRL_URLS			text
);

CREATE INDEX cc_c
	ON ccadb_certificate(CERTIFICATE_ID);

CREATE INDEX cc_mozds_c
	ON ccadb_certificate(MOZILLA_DISCLOSURE_STATUS, CERTIFICATE_ID);

CREATE INDEX cc_msds_c
	ON ccadb_certificate(MICROSOFT_DISCLOSURE_STATUS, CERTIFICATE_ID);

CREATE INDEX cc_appds_c
	ON ccadb_certificate(APPLE_DISCLOSURE_STATUS, CERTIFICATE_ID);

CREATE INDEX cc_chrds_c
	ON ccadb_certificate(CHROME_DISCLOSURE_STATUS, CERTIFICATE_ID);

CREATE TABLE ccadb_caowner (
	CA_OWNER_NAME				text,
	ORGANIZATIONAL_TYPE			text,
	GEOGRAPHIC_FOCUS			text,
	PRIMARY_MARKET				text,
	COMPANY_WEBSITE				text,
	RECOGNIZED_CAA_DOMAINS		text,
	PROBLEM_REPORTING			text
);

CREATE UNIQUE INDEX cco_caowner
	ON ccadb_caowner (CA_OWNER_NAME);


CREATE TYPE debian_arch_type AS ENUM (
	'x86_64',
	'i386',
	'ppc64'
);

CREATE TYPE debian_rnd_type AS ENUM (
	'rnd',
	'nornd',
	'noreadrnd'
);

CREATE TABLE debian_weak_key (
	RSA_KEY_SIZE				smallint,
	PROCESS_ID					smallint,
	RND							debian_rnd_type,
	ARCH						debian_arch_type,
	SHA1_MODULUS				bytea,
	CONSTRAINT dwk_pk
		PRIMARY KEY (SHA1_MODULUS)
);


CREATE TABLE microsoft_disallowedcert (
	CERTIFICATE_ID		bigint,
	DISALLOWED_HASH		bytea,
	CONSTRAINT mdc_pk
		PRIMARY KEY (CERTIFICATE_ID)
);


CREATE TYPE revocation_entry_type AS ENUM (
	'Serial Number',
	'SHA-256(Certificate)',
	'SHA-256(SubjectPublicKeyInfo)',
	'Issuer Name, Serial Number',
	'Subject Name, SHA-256(SubjectPublicKeyInfo)'
);

CREATE TABLE google_blocklist_import (
	ENTRY_SHA256	bytea,
	ENTRY_TYPE		revocation_entry_type,
	CONSTRAINT gbi_pk
		PRIMARY KEY (ENTRY_SHA256)
);

CREATE TABLE google_crlset_import (
	ISSUER_SPKI_SHA256	bytea,
	SERIAL_NUMBER		bytea,
	SPKI_SHA256			bytea,
	CONSTRAINT gci_pk
		PRIMARY KEY (ISSUER_SPKI_SHA256, SERIAL_NUMBER, SPKI_SHA256)
);

CREATE TABLE google_revoked (
	CERTIFICATE_ID		bigint,
	ENTRY_TYPE			revocation_entry_type,
	CONSTRAINT gr_pk
		PRIMARY KEY (CERTIFICATE_ID, ENTRY_TYPE)
);


CREATE TABLE mozilla_onecrl (
	CERTIFICATE_ID		bigint,
	ISSUER_CA_ID		integer,
	ISSUER_NAME			bytea,
	LAST_MODIFIED		timestamp,
	SERIAL_NUMBER		bytea,
	CREATED				timestamp,
	BUG_URL				text,
	SUMMARY				text,
	SUBJECT_NAME		bytea,
	NOT_AFTER			timestamp,
	ENTRY_TYPE			revocation_entry_type,
	CONSTRAINT mo_ca_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX mo_c
	ON mozilla_onecrl (CERTIFICATE_ID);


CREATE TABLE mozilla_cert_validation_success_import (
	SUBMISSION_DATE		date,
	RELEASE				text,
	VERSION				text,
	BIN_NUMBER			smallint,
	COUNT				bigint,
	CONSTRAINT mcvsi_pk
		PRIMARY KEY (SUBMISSION_DATE, BIN_NUMBER, RELEASE, VERSION)
);

CREATE INDEX mcvsi_bin_date_rel_ver
	ON mozilla_cert_validation_success_import (BIN_NUMBER, SUBMISSION_DATE, RELEASE, VERSION);

CREATE TABLE mozilla_cert_validation_success (
	SUBMISSION_DATE		date,
	BIN_NUMBER			smallint,
	COUNT				bigint,
	CERTIFICATE_ID		bigint,
	CONSTRAINT mcvs_pk
		PRIMARY KEY (SUBMISSION_DATE, BIN_NUMBER)
);

CREATE INDEX mcvs_bin_date
	ON mozilla_cert_validation_success (BIN_NUMBER, SUBMISSION_DATE);

CREATE TABLE mozilla_root_hashes (
	CERTIFICATE_ID		bigint,
	CERTIFICATE_SHA256	bytea,
	BIN_NUMBER			smallint,
	DISPLAY_ORDER		smallint,
	CA_OWNER			text,
	CONSTRAINT mrh_pk
		PRIMARY KEY (BIN_NUMBER, CERTIFICATE_SHA256)
);

CREATE INDEX mrh_c
	ON mozilla_root_hashes (CERTIFICATE_ID);


CREATE TABLE bugzilla_bug (
	ID								bigint,
	SUMMARY							text,
	WHITEBOARD						text,
	COMPONENT						text,
	STATUS							text,
	RESOLUTION						text,
	CREATION_TIME					timestamp,
	LAST_CHANGE_TIME				timestamp,
	LAST_CHANGE_TIME_CHECKED		timestamp,
	CONSTRAINT bb_pk
		PRIMARY KEY (ID)
);


CREATE TABLE cached_response (
	PAGE_NAME			text,
	GENERATED_AT		timestamp,
	RESPONSE_BODY		text,
	CONSTRAINT cr_pk
		PRIMARY KEY (PAGE_NAME)
);


GRANT SELECT ON ca TO guest;
GRANT SELECT ON ca TO httpd;

GRANT USAGE ON ca_id_seq TO httpd;

GRANT SELECT ON certificate TO guest;
GRANT SELECT ON certificate TO httpd;

GRANT USAGE ON certificate_id_seq TO httpd;

GRANT SELECT ON certificate_and_identities TO guest;
GRANT SELECT ON certificate_and_identities TO httpd;

GRANT SELECT ON invalid_certificate TO guest;
GRANT SELECT ON invalid_certificate TO httpd;

GRANT SELECT ON ca_certificate TO guest;
GRANT SELECT ON ca_certificate TO httpd;

GRANT SELECT ON crl TO guest;
GRANT SELECT ON crl TO httpd;

GRANT SELECT ON crl_revoked TO guest;
GRANT SELECT ON crl_revoked TO httpd;

GRANT SELECT ON ocsp_responder TO guest;
GRANT SELECT ON ocsp_responder TO httpd;

GRANT SELECT ON ca_issuer TO guest;
GRANT SELECT ON ca_issuer TO httpd;

GRANT SELECT ON ct_log TO guest;
GRANT SELECT ON ct_log TO httpd;

GRANT SELECT ON ct_log_operator TO guest;
GRANT SELECT ON ct_log_operator TO httpd;

GRANT SELECT ON ct_log_entry TO guest;
GRANT SELECT ON ct_log_entry TO httpd;

GRANT SELECT ON accepted_roots TO guest;
GRANT SELECT ON accepted_roots TO httpd;

GRANT SELECT ON linter_version TO guest;
GRANT SELECT ON linter_version TO httpd;

GRANT SELECT ON lint_issue TO guest;
GRANT SELECT ON lint_issue TO httpd;

GRANT SELECT ON lint_cert_issue TO guest;
GRANT SELECT ON lint_cert_issue TO httpd;

GRANT SELECT ON lint_summary TO guest;
GRANT SELECT ON lint_summary TO httpd;

GRANT SELECT ON trust_context TO guest;
GRANT SELECT ON trust_context TO httpd;

GRANT SELECT ON trust_purpose TO guest;
GRANT SELECT ON trust_purpose TO httpd;

GRANT SELECT ON root_trust_purpose TO guest;
GRANT SELECT ON root_trust_purpose TO httpd;

GRANT SELECT ON ca_trust_purpose TO guest;
GRANT SELECT ON ca_trust_purpose TO httpd;

GRANT SELECT ON applicable_purpose TO guest;
GRANT SELECT ON applicable_purpose TO httpd;

GRANT SELECT ON ccadb_certificate TO guest;
GRANT SELECT ON ccadb_certificate TO httpd;

GRANT SELECT ON ccadb_caowner TO guest;
GRANT SELECT ON ccadb_caowner TO httpd;

GRANT SELECT ON debian_weak_key TO guest;
GRANT SELECT ON debian_weak_key TO httpd;

GRANT SELECT ON microsoft_disallowedcert TO guest;
GRANT SELECT ON microsoft_disallowedcert TO httpd;

GRANT SELECT ON mozilla_onecrl TO guest;
GRANT SELECT ON mozilla_onecrl TO httpd;

GRANT SELECT ON google_revoked TO guest;
GRANT SELECT ON google_revoked TO httpd;

GRANT SELECT ON mozilla_cert_validation_success_import TO guest;
GRANT SELECT ON mozilla_cert_validation_success_import TO httpd;

GRANT SELECT ON mozilla_cert_validation_success TO guest;
GRANT SELECT ON mozilla_cert_validation_success TO httpd;

GRANT SELECT ON mozilla_root_hashes TO guest;
GRANT SELECT ON mozilla_root_hashes TO httpd;

GRANT SELECT ON bugzilla_bug TO guest;
GRANT SELECT ON bugzilla_bug TO httpd;

GRANT SELECT ON cached_response TO guest;
GRANT SELECT ON cached_response TO httpd;


\i fnc/ci_error_message.fnc
\i fnc/crl_update.fnc
\i fnc/determine_ca_trust_purposes.fnc
\i fnc/download_cert.fnc
\i fnc/enumerate_chains.fnc
\i fnc/generate_add_chain_body.fnc
\i fnc/get_ca_name_attribute.fnc
\i fnc/get_parameter.fnc
\i fnc/getsth_update.fnc
\i fnc/html_escape.fnc
\i fnc/find_issuer.fnc
\i fnc/import_any_cert.fnc
\i fnc/import_cert.fnc
\i fnc/import_leaf_certs.fnc
\i fnc/is_technically_constrained.fnc
\i fnc/process_cert_urls.fnc
\i fnc/process_expirations.fnc
\i fnc/serial_number_bitlength.fnc
\i fnc/web_apis.fnc

\i ccadb/ccadb_disclosure_group.fnc
\i ccadb/ccadb_disclosure_group_summary.fnc
\i ccadb/ccadb_disclosure_group2.fnc
\i ccadb/disclosure_problems.fnc
\i ccadb/microsoft_disclosures.fnc
\i ccadb/mozilla_disclosures.fnc
\i libocsppq/ocsp_embedded.fnc
\i libocsppq/ocsp_randomserial_embedded.fnc
\i libzlintpq/zlint_embedded.fnc
\i ocsp_responders/ocsp_responders.fnc
\i ocsp_responders/ocsp_response.fnc
\i revoked_intermediates/revoked_intermediates.fnc
\i test_websites/test_websites.fnc


CREATE VIEW certificate_identity AS
SELECT NULL::bigint		CERTIFICATE_ID,
		NULL::text		NAME_TYPE,
		NULL::text		NAME_VALUE,
		NULL::integer	ISSUER_CA_ID
	FROM ci_error_message();

GRANT SELECT ON certificate_identity TO guest;


CREATE VIEW certificate_lifecycle AS
SELECT c.ID CERTIFICATE_ID,
		c.ISSUER_CA_ID CA_ID,
		encode(x509_serialNumber(c.CERTIFICATE), 'hex') SERIAL_NUMBER,
		x509_subjectName(c.CERTIFICATE) SUBJECT_DISTINGUISHED_NAME,
		(CASE WHEN x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE)
			THEN 'Precertificate'
			ELSE 'Certificate'
		END) CERTIFICATE_TYPE,
		x509_notBefore(c.CERTIFICATE) NOT_BEFORE,
		x509_notAfter(c.CERTIFICATE) NOT_AFTER,
		ctle.FIRST_SEEN FIRST_SEEN,
		coalesce(crlr.REVOKED, 0) REVOKED,
		coalesce(lci.LINT_ERRORS, 0) LINT_ERRORS,
		(x509_notAfter(c.CERTIFICATE) < now() AT TIME ZONE 'UTC') EXPIRED
	FROM certificate c
			JOIN LATERAL (
				SELECT MIN(ctle.ENTRY_TIMESTAMP) FIRST_SEEN,
						ctle.CERTIFICATE_ID
					FROM ct_log_entry ctle
					WHERE ctle.CERTIFICATE_ID = c.ID
					GROUP BY ctle.CERTIFICATE_ID
			) ctle ON TRUE
			LEFT JOIN LATERAL (
				SELECT count(crlr.CA_ID) REVOKED,
						crlr.SERIAL_NUMBER
					FROM crl_revoked crlr
					WHERE crlr.CA_ID = c.ISSUER_CA_ID
						AND crlr.SERIAL_NUMBER = x509_serialNumber(c.CERTIFICATE)
					GROUP BY crlr.SERIAL_NUMBER
			) crlr ON TRUE
			LEFT JOIN LATERAL (
				SELECT count(lci.CERTIFICATE_ID) LINT_ERRORS,
						lci.CERTIFICATE_ID
					FROM lint_cert_issue lci
					WHERE lci.CERTIFICATE_ID = c.ID
					GROUP BY lci.CERTIFICATE_ID
			) lci ON TRUE;

GRANT SELECT ON certificate_lifecycle TO guest;
