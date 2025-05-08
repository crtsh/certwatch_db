\timing on

\set ON_ERROR_STOP on

BEGIN WORK;

\echo Importing All CCADB Included Root Certificate Trust Bit Settings

CREATE TEMPORARY TABLE ccadb_root_trust_bit_import (
	CA_OWNER					text,
	CERT_NAME					text,
	APPLE_STATUS				text,
	APPLE_TRUST_BITS			text,
	CHROME_STATUS				text,
	MICROSOFT_STATUS			text,
	MICROSOFT_EKUS				text,
	MOZILLA_STATUS				text,
	MOZILLA_TRUST_BITS			text,
	CERT_SHA256					text
) ON COMMIT DROP;

\COPY ccadb_root_trust_bit_import FROM 'ccadb_all_root_trust_bits.csv' CSV HEADER;

UPDATE ccadb_certificate cc
	SET APPLE_TRUST_BITS = crtbi.APPLE_TRUST_BITS,
		MICROSOFT_EKUS = crtbi.MICROSOFT_EKUS,
		MOZILLA_TRUST_BITS = crtbi.MOZILLA_TRUST_BITS
	FROM ccadb_root_trust_bit_import crtbi
	WHERE cc.CERT_SHA256 = decode(crtbi.CERT_SHA256, 'hex');

COMMIT WORK;
