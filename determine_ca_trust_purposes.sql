\timing

CREATE TABLE ca_trust_purpose_temp ( LIKE ca_trust_purpose INCLUDING INDEXES);

CREATE INDEX ctpt_lc
	ON ca_trust_purpose_temp (LONGEST_CHAIN, PATH_LEN_CONSTRAINT, TRUST_PURPOSE_ID, CA_ID);

SELECT determine_ca_trust_purposes();

BEGIN WORK;

LOCK ca_trust_purpose;

TRUNCATE ca_trust_purpose;

INSERT INTO ca_trust_purpose
	SELECT * FROM ca_trust_purpose_temp;

COMMIT WORK;

CLUSTER ca_trust_purpose USING ctp_pk;

DROP TABLE ca_trust_purpose_temp;

