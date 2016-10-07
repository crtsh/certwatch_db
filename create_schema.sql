-- Run libx509pq/create_functions.sql first.


-- As the "postgres" user.

CREATE EXTENSION pgcrypto;


-- As the "certwatch" user.

CREATE TABLE ca (
	ID						serial,
	NAME					text		NOT NULL,
	PUBLIC_KEY				bytea		NOT NULL,
	BRAND					text,
	LINTING_APPLIES			boolean		DEFAULT TRUE,
	NO_OF_CERTS_ISSUED		bigint		DEFAULT 0	NOT NULL,
	CONSTRAINT ca_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX ca_uniq
	ON ca (NAME text_pattern_ops, PUBLIC_KEY);

CREATE INDEX ca_name
	ON ca (lower(NAME) text_pattern_ops);

CREATE INDEX ca_brand
	ON ca (lower(BRAND) text_pattern_ops);

CREATE INDEX ca_name_reverse
	ON ca (reverse(lower(NAME)) text_pattern_ops);

CREATE INDEX ca_brand_reverse
	ON ca (reverse(lower(BRAND)) text_pattern_ops);

CREATE INDEX ca_linting_applies
	ON ca (LINTING_APPLIES, ID);

CREATE INDEX ca_spki_sha256
	ON ca (digest(PUBLIC_KEY, 'sha256'));

CREATE TABLE certificate (
	ID						serial,
	CERTIFICATE				bytea		NOT NULL,
	ISSUER_CA_ID			integer		NOT NULL,
	CABLINT_CACHED_AT		timestamp,
	X509LINT_CACHED_AT		timestamp,
	CONSTRAINT c_pk
		PRIMARY KEY (ID),
	CONSTRAINT c_ica_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX c_ica_typecanissue
	ON certificate (ISSUER_CA_ID, x509_canIssueCerts(CERTIFICATE));

CREATE INDEX c_ica_notbefore
	ON certificate (ISSUER_CA_ID, x509_notBefore(CERTIFICATE));

CREATE INDEX c_notafter_ica
	ON certificate (x509_notAfter(CERTIFICATE), ISSUER_CA_ID);

CREATE INDEX c_serial_ica
	ON certificate (x509_serialNumber(CERTIFICATE), ISSUER_CA_ID);

CREATE INDEX c_sha1
	ON certificate (digest(CERTIFICATE, 'sha1'));

CREATE UNIQUE INDEX c_sha256
	ON certificate (digest(CERTIFICATE, 'sha256'));

CREATE INDEX c_ski
	ON certificate (x509_subjectKeyIdentifier(CERTIFICATE));

CREATE INDEX c_pubkey_md5
	ON certificate (x509_publicKeyMD5(CERTIFICATE));

CREATE INDEX c_spki_sha1
	ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha1'));

CREATE INDEX c_spki_sha256
	ON certificate (digest(x509_publicKey(CERTIFICATE), 'sha256'));

CREATE INDEX c_subject_sha1
	ON certificate (digest(x509_name(CERTIFICATE), 'sha1'));

CREATE TABLE invalid_certificate (
	ID						serial,
	CERTIFICATE_ID			integer,
	PROBLEMS				text,
	CERTIFICATE_AS_LOGGED	bytea,
	CONSTRAINT ic_pk
		PRIMARY KEY (ID),
	CONSTRAINT ic_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID)
);

CREATE TYPE name_type AS ENUM (
	'commonName', 'organizationName', 'emailAddress',
	'rfc822Name', 'dNSName', 'iPAddress', 'organizationalUnitName'
);

CREATE TABLE certificate_identity (
	CERTIFICATE_ID			integer		NOT NULL,
	NAME_TYPE				name_type	NOT NULL,
	NAME_VALUE				text		NOT NULL,
	ISSUER_CA_ID			integer,
	CONSTRAINT ci_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID),
	CONSTRAINT ci_ca_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

CREATE UNIQUE INDEX ci_uniq
	ON certificate_identity (CERTIFICATE_ID, lower(NAME_VALUE) text_pattern_ops, NAME_TYPE);

CREATE INDEX ci_forward
	ON certificate_identity (lower(NAME_VALUE) text_pattern_ops, ISSUER_CA_ID, NAME_TYPE);

CREATE INDEX ci_reverse
	ON certificate_identity (reverse(lower(NAME_VALUE)) text_pattern_ops, ISSUER_CA_ID, NAME_TYPE);

CREATE INDEX ci_ca
	ON certificate_identity (ISSUER_CA_ID, lower(NAME_VALUE) text_pattern_ops, NAME_TYPE);

CREATE INDEX ci_ca_reverse
	ON certificate_identity (ISSUER_CA_ID, reverse(lower(NAME_VALUE)) text_pattern_ops, NAME_TYPE);


CREATE TABLE ca_certificate (
	CERTIFICATE_ID			integer,
	CA_ID					integer,
	CONSTRAINT cac_pk
		PRIMARY KEY (CERTIFICATE_ID),
	CONSTRAINT cac_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID),
	CONSTRAINT cac_ca_fk
		FOREIGN KEY (CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX cac_ca_cert
	ON ca_certificate (CA_ID, CERTIFICATE_ID);


CREATE TABLE ct_log (
	ID						smallint,
	URL						text,
	NAME					text,
	PUBLIC_KEY				bytea,
	LATEST_ENTRY_ID			integer,
	LATEST_UPDATE			timestamp,
	OPERATOR				text,
	INCLUDED_IN_CHROME		integer,
	IS_ACTIVE				boolean,
	LATEST_STH_TIMESTAMP	timestamp,
	MMD_IN_SECONDS			integer,
	CHROME_ISSUE_NUMBER		integer,
	NON_INCLUSION_STATUS	text,
	CONSTRAINT ctl_pk
		PRIMARY KEY (ID),
	CONSTRAINT crl_url_unq
		UNIQUE (URL)
);

CREATE UNIQUE INDEX ctl_sha256_pubkey
	ON ct_log (digest(PUBLIC_KEY, 'sha256'));

CREATE TABLE ct_log_entry (
	CERTIFICATE_ID	integer,
	CT_LOG_ID		smallint,
	ENTRY_ID		integer,
	ENTRY_TIMESTAMP	timestamp,
	CONSTRAINT ctle_pk
		PRIMARY KEY (CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID),
	CONSTRAINT ctle_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID),
	CONSTRAINT ctle_ctl_fk
		FOREIGN KEY (CT_LOG_ID)
		REFERENCES ct_log(ID)
);

CREATE INDEX ctle_le
	ON ct_log_entry (CT_LOG_ID, ENTRY_ID);

CREATE INDEX ctle_el
	ON ct_log_entry (ENTRY_ID, CT_LOG_ID);

CREATE TYPE linter_type AS ENUM (
	'cablint', 'x509lint'
);

CREATE TABLE linter_version (
	VERSION_STRING	text,
	GIT_COMMIT		bytea,
	DEPLOYED_AT		timestamp,
	LINTER			linter_type
);

CREATE UNIQUE INDEX lv_li_da
	ON linter_version(LINTER, DEPLOYED_AT);


CREATE TABLE lint_issue (
	ID				serial,
	SEVERITY		text,
	ISSUE_TEXT		text,
	LINTER			linter_type,
	CONSTRAINT li_pk
		PRIMARY KEY (ID),
	CONSTRAINT li_it_unq
		UNIQUE (SEVERITY, ISSUE_TEXT),
	CONSTRAINT li_li_se_it_unq
		UNIQUE (LINTER, SEVERITY, ISSUE_TEXT)
);

CREATE TABLE lint_cert_issue (
	ID					bigserial,
	CERTIFICATE_ID		integer,
	LINT_ISSUE_ID		integer,
	ISSUER_CA_ID		integer,
	NOT_BEFORE			timestamp,
	CONSTRAINT lci_pk
		PRIMARY KEY (ID),
	CONSTRAINT lci_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID),
	CONSTRAINT lci_ci_fk
		FOREIGN KEY (LINT_ISSUE_ID)
		REFERENCES lint_issue(ID),
	CONSTRAINT lci_ca_fk
		FOREIGN KEY (ISSUER_CA_ID)
		REFERENCES ca(ID)
);

CREATE INDEX lci_c_ci
	ON lint_cert_issue (CERTIFICATE_ID, LINT_ISSUE_ID);

CREATE INDEX lci_ca_ci_nb_c
	ON lint_cert_issue (ISSUER_CA_ID, LINT_ISSUE_ID, NOT_BEFORE, CERTIFICATE_ID);

CREATE INDEX lci_ci_nb
	ON lint_cert_issue (LINT_ISSUE_ID, NOT_BEFORE);

CREATE INDEX lci_nb_ca_ci
	ON lint_cert_issue (NOT_BEFORE, ISSUER_CA_ID, LINT_ISSUE_ID);


CREATE TABLE trust_context (
	ID				integer,
	CTX				text		NOT NULL,
	URL				text,
	VERSION			text,
	VERSION_URL		text,
	DISPLAY_ORDER	integer,
	CONSTRAINT tc_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX tc_ctx_uniq
	ON trust_context (CTX text_pattern_ops);

INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 1, 'Microsoft', 'https://aka.ms/rootcert' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 5, 'Mozilla', 'https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 6, 'Chrome', 'https://www.chromium.org/Home/chromium-security/root-ca-policy' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 9, 'Adobe AATL', 'https://helpx.adobe.com/acrobat/kb/approved-trust-list2.html' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 12, 'Apple', 'https://www.apple.com/certificateauthority/ca_program.html' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 23, 'Java', 'http://www.oracle.com/technetwork/java/javase/javasecarootcertsprogram-1876540.html' );
INSERT INTO trust_context ( ID, CTX, URL ) VALUES ( 24, 'Adobe EUTL', 'https://blogs.adobe.com/documentcloud/eu-trusted-list-now-available-in-adobe-acrobat/' );


CREATE TABLE trust_purpose (
	ID					integer,
	PURPOSE				text,
	PURPOSE_OID			text,
	EARLIEST_NOT_BEFORE	timestamp,
	LATEST_NOT_AFTER	timestamp,
	DISPLAY_ORDER		integer,
	CONSTRAINT tp_pk
		PRIMARY KEY (ID)
);

CREATE UNIQUE INDEX tp_purpose_uniq
	ON trust_purpose (PURPOSE text_pattern_ops, PURPOSE_OID text_pattern_ops);

INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 1, 'Server Authentication', '1.3.6.1.5.5.7.3.1', 2 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 2, 'Client Authentication', '1.3.6.1.5.5.7.3.2', 10 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 3, 'Secure Email', '1.3.6.1.5.5.7.3.4', 11 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 4, 'Code Signing', '1.3.6.1.5.5.7.3.3', 20 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 5, 'Time Stamping', '1.3.6.1.5.5.7.3.8', 21 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 6, 'OCSP Signing', '1.3.6.1.5.5.7.3.9', 30 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 7, 'Document Signing', '1.3.6.1.4.1.311.10.3.12', 31 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 8, 'Encrypting File System', '1.3.6.1.4.1.311.10.3.4', 32 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 9, 'IP security end system', '1.3.6.1.5.5.7.3.5', 40 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 10, 'IP security IKE intermediate', '1.3.6.1.5.5.8.2.2', 41 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 11, 'IP security tunnel termination', '1.3.6.1.5.5.7.3.6', 42 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 12, 'IP security user', '1.3.6.1.5.5.7.3.7', 43 );
INSERT INTO trust_purpose ( ID, PURPOSE, PURPOSE_OID, DISPLAY_ORDER ) VALUES ( 14, 'Adobe Authentic Document', '1.2.840.113583.1.1.5', 44 );

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

CREATE TABLE applicable_purpose(
	TRUST_CONTEXT_ID	integer,
	PURPOSE				text
);

INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Client Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 1, 'Code Signing' );
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
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 5, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 6, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 6, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Document Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 9, 'Adobe Authentic Document' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'EV Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'IP security user' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 12, 'Time Stamping' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 23, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 23, 'Server Authentication' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Code Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Document Signing' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Secure Email' );
INSERT INTO applicable_purpose ( TRUST_CONTEXT_ID, PURPOSE ) VALUES ( 24, 'Adobe Authentic Document' );


CREATE TABLE root_trust_purpose(
	CERTIFICATE_ID		integer,
	TRUST_CONTEXT_ID	integer,
	TRUST_PURPOSE_ID	integer,
	CONSTRAINT rtp_pk
		PRIMARY KEY (CERTIFICATE_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID),
	CONSTRAINT rtp_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID),
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
	'Undisclosed',
	'AllServerAuthPathsRevoked',
	'NoKnownServerAuthTrustPath',
	'TechnicallyConstrained',
	'Expired',
	'Revoked',
	'RevokedViaOneCRL',
	'Disclosed',
	'DisclosedWithErrors'
);


CREATE TABLE microsoft_disallowedcert_import (
	PUBLIC_KEY_MD5		bytea,
	CONSTRAINT mdci_pk
		PRIMARY KEY (PUBLIC_KEY_MD5)
);

CREATE TABLE microsoft_disallowedcert (
	CERTIFICATE_ID		integer,
	PUBLIC_KEY_MD5		bytea,
	CONSTRAINT mdc_pk
		PRIMARY KEY (CERTIFICATE_ID),
	CONSTRAINT mdc_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID)
);


CREATE TYPE revocation_entry_type AS ENUM (
	'Serial Number',
	'SHA-256(Certificate)',
	'SHA-256(SubjectPublicKeyInfo)'
);

CREATE TABLE google_blacklist_import (
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
	CERTIFICATE_ID		integer,
	ENTRY_TYPE			revocation_entry_type,
	CONSTRAINT gr_pk
		PRIMARY KEY (CERTIFICATE_ID, ENTRY_TYPE),
	CONSTRAINT gr_c_fk
		FOREIGN KEY (CERTIFICATE_ID)
		REFERENCES certificate(ID)
);


GRANT SELECT ON ca TO crtsh;

GRANT USAGE ON ca_id_seq TO crtsh;

GRANT SELECT ON certificate TO crtsh;

GRANT USAGE ON certificate_id_seq TO crtsh;

GRANT SELECT ON invalid_certificate TO crtsh;

GRANT SELECT ON certificate_identity TO crtsh;

GRANT SELECT ON ca_certificate TO crtsh;

GRANT SELECT ON ct_log TO crtsh;

GRANT SELECT ON ct_log_entry TO crtsh;

GRANT SELECT ON lint_issue TO crtsh;

GRANT SELECT ON lint_cert_issue TO crtsh;

GRANT SELECT ON trust_context TO crtsh;

GRANT SELECT ON trust_purpose TO crtsh;

GRANT SELECT ON root_trust_purpose TO crtsh;

GRANT SELECT ON ca_trust_purpose TO crtsh;

GRANT SELECT ON applicable_purpose TO crtsh;

GRANT SELECT ON microsoft_disallowedcert TO crtsh;

GRANT SELECT ON mozilla_onecrl TO crtsh;

GRANT SELECT ON google_revoked TO crtsh;

\i lint_cached.fnc
\i download_cert.fnc
\i extract_cert_names.fnc
\i get_ca_primary_name_attribute.fnc
\i get_parameter.fnc
\i html_escape.fnc
\i import_cert.fnc
\i import_ct_cert.fnc
\i web_apis.fnc
