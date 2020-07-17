CREATE OR REPLACE FUNCTION build_graph(
	cert_id					certificate.ID%TYPE,
	must_be_time_valid		boolean					DEFAULT TRUE,
	trust_ctx_id			trust_context.ID%TYPE	DEFAULT NULL,
	trust_purp_id			trust_purpose.ID%TYPE	DEFAULT NULL,
	max_chain_length		integer					DEFAULT 5,
	certchain_so_far		text[]					DEFAULT NULL,
	cachain_so_far			integer[]				DEFAULT NULL
) RETURNS SETOF text[]
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_notAfter			timestamp;
	t_caID				ca.ID%TYPE;
	t_validity			text;
	t_caChainSoFar		integer[];
	t_count				integer;
	l_record			RECORD;
	l_chain				RECORD;
BEGIN
	SELECT c.CERTIFICATE, c.ISSUER_CA_ID, x509_notAfter(c.CERTIFICATE), cac.CA_ID
		INTO t_certificate, t_issuerCAID, t_notAfter, t_caID
		FROM certificate c
				LEFT OUTER JOIN ca_certificate cac ON (
					c.ID = cac.CERTIFICATE_ID
				)
		WHERE c.ID = cert_id;
	IF t_certificate IS NULL THEN
		RETURN;
	END IF;

	IF must_be_time_valid AND ((now() AT TIME ZONE 'UTC') NOT BETWEEN (x509_notBefore(t_certificate) AT TIME ZONE 'UTC') AND (x509_notAfter(t_certificate) AT TIME ZONE 'UTC')) THEN
		RETURN;
	END IF;

	IF t_notAfter > now() AT TIME ZONE 'UTC' THEN
		t_validity := 'valid';
	ELSE
		t_validity := 'expired';
	END IF;

	IF trust_ctx_id IS NOT NULL THEN
		FOR l_record IN (
			SELECT tc.CTX
				FROM root_trust_purpose rtp, trust_context tc
				WHERE rtp.CERTIFICATE_ID = cert_id
					AND rtp.TRUST_CONTEXT_ID = coalesce(nullif(trust_ctx_id, 0), rtp.TRUST_CONTEXT_ID)
					AND rtp.TRUST_PURPOSE_ID = coalesce(nullif(trust_purp_id, 0), rtp.TRUST_PURPOSE_ID)
					AND rtp.TRUST_CONTEXT_ID = tc.ID
				GROUP BY tc.CTX
		) LOOP
			RETURN NEXT certchain_so_far || (cert_id::text || ':trust_' || upper(l_record.CTX) || ';' || t_validity);
		END LOOP;
	END IF;

	-- Enforce any Basic Constraints pathLenConstraint in this certificate.
	IF (COALESCE(x509_getPathLenConstraint(t_certificate)::bigint,
					array_length(certchain_so_far, 1)) + 1)
			< array_length(certchain_so_far, 1) THEN
		RETURN;
	END IF;

	-- Enforce a maximum path length (default: 5 certificates).
	IF array_length(certchain_so_far, 1) >= max_chain_length THEN
		RETURN;
	END IF;

	-- Avoid cross-certification loops!
	IF (cachain_so_far IS NOT NULL) AND (cachain_so_far @> ARRAY[t_issuerCAID]) THEN
		IF array_length(cachain_so_far, 1) - array_length(array_remove(cachain_so_far, t_issuerCAID), 1) > 0 THEN
			RETURN;
		END IF;
	END IF;
	t_caChainSoFar := cachain_so_far || t_issuerCAID;

	-- We have a partial chain, so loop through every matching issuer CA certificate.
	FOR l_record IN (
				SELECT cac.CERTIFICATE_ID, cac.CA_ID
					FROM certificate c, ca, ca_certificate cac
					WHERE c.ID = cert_id
						AND c.ISSUER_CA_ID != coalesce(t_caID, -1)
						AND c.ISSUER_CA_ID = ca.ID
						AND ca.PUBLIC_KEY != E'\\x00'
						AND ca.ID = cac.CA_ID
					ORDER BY ca.ID DESC
			) LOOP
		IF (trust_ctx_id IS NOT NULL) OR (trust_purp_id IS NOT NULL) THEN
			SELECT COUNT(*)
				INTO t_count
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = l_record.CA_ID
					AND ctp.TRUST_CONTEXT_ID = COALESCE(NULLIF(trust_ctx_id, 0),
														ctp.TRUST_CONTEXT_ID)
					AND ctp.TRUST_PURPOSE_ID = COALESCE(NULLIF(trust_purp_id, 0),
														ctp.TRUST_PURPOSE_ID)
					AND ctp.IS_TIME_VALID >= COALESCE(must_be_time_valid, FALSE)
					AND coalesce(ctp.NOTBEFORE_UNTIL, 'infinity'::date) > x509_notBefore(t_certificate);
			IF (t_count > 0) AND (trust_purp_id >= 100) THEN	-- EV Server Authentication.
				-- EV Server Authentication must also be trusted for Server Authentication.
				SELECT COUNT(*)
					INTO t_count
					FROM ca_trust_purpose ctp
					WHERE ctp.CA_ID = l_record.CA_ID
						AND ctp.TRUST_CONTEXT_ID = COALESCE(NULLIF(trust_ctx_id, 0),
															ctp.TRUST_CONTEXT_ID)
						AND ctp.TRUST_PURPOSE_ID IN (1, 30);	-- Server Authentication, SGC.
			END IF;
		ELSE
			t_count := 1;
		END IF;
		IF t_count > 0 THEN
			RETURN QUERY SELECT build_graph(
				l_record.CERTIFICATE_ID, must_be_time_valid, trust_ctx_id, trust_purp_id, max_chain_length,
				certchain_so_far || (cert_id::text || ':' || l_record.CA_ID || ';' || t_validity), t_caChainSoFar
			);
		END IF;
	END LOOP;

	-- No trust context, so output this partial chain.
	IF trust_ctx_id IS NULL THEN
		RETURN NEXT certchain_so_far || (cert_id::text || ':' || t_issuerCAID::text || ';' || t_validity);
	END IF;
END;
$$ LANGUAGE plpgsql;
