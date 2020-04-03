\timing on

\set ON_ERROR_STOP on

BEGIN WORK;

CREATE TEMPORARY TABLE ca_trust_purpose_temp ( LIKE ca_trust_purpose INCLUDING INDEXES)
	ON COMMIT DROP;

CREATE INDEX ctpt_lc
	ON ca_trust_purpose_temp (ITERATION_LAST_MODIFIED, TRUST_PURPOSE_ID, CA_ID, TRUST_CONTEXT_ID);

SELECT determine_ca_trust_purposes();

LOCK TABLE ca_trust_purpose;

TRUNCATE ca_trust_purpose;

INSERT INTO ca_trust_purpose
	SELECT * FROM ca_trust_purpose_temp;

COMMIT WORK;

CLUSTER ca_trust_purpose USING ctp_pk;
