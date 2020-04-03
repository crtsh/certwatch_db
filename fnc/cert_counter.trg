CREATE OR REPLACE FUNCTION cert_counter(
) RETURNS TRIGGER
AS $$
DECLARE
	t_notAfter				timestamp;
	t_countIndex			smallint	:= 1;	-- Certificate.
BEGIN
	t_notAfter := coalesce(x509_notAfter(coalesce(new.CERTIFICATE, old.CERTIFICATE)), 'infinity'::timestamp);

	IF x509_hasExtension(coalesce(new.CERTIFICATE, old.CERTIFICATE), '1.3.6.1.4.1.11129.2.4.3', TRUE) THEN
		t_countIndex := 2;		-- Precertificate (RFC6962).
	END IF;

	IF TG_OP = 'UPDATE' THEN
		IF (old.ID != new.ID) OR (old.CERTIFICATE != new.CERTIFICATE) THEN
			RAISE EXCEPTION 'Sorry, ISSUER_CA_ID is the only "certificate" field that can be UPDATEd.';
		ELSIF old.ISSUER_CA_ID = new.ISSUER_CA_ID THEN
			RETURN new;
		END IF;
		RAISE EXCEPTION 'Updating ISSUER_CA_ID is not currently permitted because... TODO: Update lint_summarizer to handle "UPDATE lint_cert_issue SET ISSUER_CA_ID = new.ISSUER_CA_ID".';
		UPDATE lint_cert_issue
			SET ISSUER_CA_ID = new.ISSUER_CA_ID
			WHERE CERTIFICATE_ID = new.ID;

		UPDATE ca
			SET NUM_ISSUED[t_countIndex] = coalesce(NUM_ISSUED[t_countIndex], 0) + 1,
				NUM_EXPIRED[t_countIndex] = coalesce(NUM_EXPIRED[t_countIndex], 0) + CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN 1 ELSE 0 END,
				NEXT_NOT_AFTER = CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN NEXT_NOT_AFTER ELSE least(coalesce(NEXT_NOT_AFTER, 'infinity'::timestamp), t_notAfter) END
			WHERE ID = new.ISSUER_CA_ID;
	END IF;

	IF TG_OP IN ('UPDATE', 'DELETE') THEN
		UPDATE ca
			SET NUM_ISSUED[t_countIndex] = coalesce(NUM_ISSUED[t_countIndex], 0) - 1,
				NUM_EXPIRED[t_countIndex] = coalesce(NUM_EXPIRED[t_countIndex], 0) - CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN 1 ELSE 0 END
			WHERE ID = old.ISSUER_CA_ID;
	END IF;

	IF TG_OP = 'DELETE' THEN
		RETURN old;
	ELSE
		RETURN new;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
