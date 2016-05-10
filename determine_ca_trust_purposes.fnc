CREATE OR REPLACE FUNCTION determine_ca_trust_purposes(
	max_iterations			integer		DEFAULT 20
) RETURNS integer
AS $$
DECLARE
	l_rtp				RECORD;
	l_ctp				RECORD;
	t_iterations		integer		:= 0;
	t_rowsAdded			integer;
	t_count				integer;
	t_addThis			boolean;
	t_caID				ca.ID%TYPE;
BEGIN
	TRUNCATE ca_trust_purpose;

	INSERT INTO ca_trust_purpose (
			CA_ID, TRUST_CONTEXT_ID, TRUST_PURPOSE_ID, PATH_LEN_CONSTRAINT,
			EARLIEST_NOT_BEFORE, LATEST_NOT_AFTER
		)
		SELECT cac.CA_ID, rtp.TRUST_CONTEXT_ID, rtp.TRUST_PURPOSE_ID, max_iterations,
				min(x509_notBefore(c.CERTIFICATE)), max(x509_notAfter(c.CERTIFICATE))
			FROM root_trust_purpose rtp, ca_certificate cac, certificate c
			WHERE rtp.CERTIFICATE_ID = cac.CERTIFICATE_ID
				AND cac.CERTIFICATE_ID = c.ID
			GROUP BY cac.CA_ID, rtp.TRUST_CONTEXT_ID,
					rtp.TRUST_PURPOSE_ID;

	WHILE t_iterations < max_iterations LOOP
		t_rowsAdded := 0;
		FOR l_ctp IN (
					SELECT ctp.TRUST_CONTEXT_ID, ctp.TRUST_PURPOSE_ID,
							c.ID, c.ISSUER_CA_ID, c.CERTIFICATE,
							tp.PURPOSE, tp.PURPOSE_OID,
							ctp.PATH_LEN_CONSTRAINT,
							ctp.EARLIEST_NOT_BEFORE, ctp.LATEST_NOT_AFTER
						FROM ca_trust_purpose ctp, trust_purpose tp,
							certificate c
						WHERE ctp.PATH_LEN_CONSTRAINT BETWEEN 1 AND (max_iterations - t_iterations)
							AND ctp.TRUST_PURPOSE_ID = tp.ID
							AND ctp.CA_ID = c.ISSUER_CA_ID
							AND x509_canIssueCerts(c.CERTIFICATE)
				) LOOP
			BEGIN
				SELECT cac.CA_ID
					INTO t_caID
					FROM ca_certificate cac
					WHERE cac.CERTIFICATE_ID = l_ctp.ID;
				t_addThis := FALSE;
				IF l_ctp.PURPOSE = 'EV Server Authentication' THEN
					IF x509_isPolicyPermitted(l_ctp.CERTIFICATE,
												l_ctp.PURPOSE_OID) THEN
						IF x509_isEKUPermitted(l_ctp.CERTIFICATE,
												'1.3.6.1.5.5.7.3.1')
								OR x509_isEKUPermitted(l_ctp.CERTIFICATE,
												'1.3.6.1.4.1.311.10.3.3') THEN
							-- This EV Policy OID is permitted, and so is Server
							-- Authentication and/or SGC.
							t_addThis := TRUE;
						END IF;
					END IF;
				ELSIF x509_isEKUPermitted(l_ctp.CERTIFICATE,
											l_ctp.PURPOSE_OID) THEN
					t_addThis := TRUE;
				ELSIF (l_ctp.PURPOSE_OID = '1.3.6.1.5.5.7.3.1')
						AND x509_isEKUPermitted(l_ctp.CERTIFICATE,
												'1.3.6.1.4.1.311.10.3.3') THEN
					-- If SGC is present but Server Authentication is not
					-- present, act as if Server Authentication is present.
					t_addThis := TRUE;
				END IF;
				IF t_addThis THEN
					INSERT INTO ca_trust_purpose (
							CA_ID,
							TRUST_CONTEXT_ID,
							TRUST_PURPOSE_ID,
							PATH_LEN_CONSTRAINT,
							EARLIEST_NOT_BEFORE,
							LATEST_NOT_AFTER
						)
						VALUES (
							coalesce(t_caID, -l_ctp.ID),
							-- -l_ctp.ID will generate an exception.  This is
							-- intentional.
							l_ctp.TRUST_CONTEXT_ID,
							l_ctp.TRUST_PURPOSE_ID,
							greatest(
								0,
								least(l_ctp.PATH_LEN_CONSTRAINT - 1,
										coalesce(x509_getPathLenConstraint(l_ctp.CERTIFICATE),
													max_iterations)
								)
							),
							greatest(l_ctp.EARLIEST_NOT_BEFORE, x509_notBefore(l_ctp.CERTIFICATE)),
							least(l_ctp.LATEST_NOT_AFTER, x509_notAfter(l_ctp.CERTIFICATE))
						);
					t_rowsAdded := t_rowsAdded + 1;
				END IF;
			EXCEPTION
				WHEN unique_violation THEN
					IF t_addThis THEN
						UPDATE ca_trust_purpose
							SET PATH_LEN_CONSTRAINT = greatest(
									PATH_LEN_CONSTRAINT,
									least(
										l_ctp.PATH_LEN_CONSTRAINT - 1,
										coalesce(x509_getPathLenConstraint(l_ctp.CERTIFICATE),
													max_iterations)
									)
								),
								EARLIEST_NOT_BEFORE = greatest(
									EARLIEST_NOT_BEFORE,
									x509_notBefore(l_ctp.CERTIFICATE)
								),
								LATEST_NOT_AFTER = least(
									LATEST_NOT_AFTER,
									x509_notAfter(l_ctp.CERTIFICATE)
								)
							WHERE CA_ID = coalesce(t_caID, -l_ctp.ID)
								AND TRUST_CONTEXT_ID = l_ctp.TRUST_CONTEXT_ID
								AND TRUST_PURPOSE_ID = l_ctp.TRUST_PURPOSE_ID;
					END IF;
			END;
		END LOOP;
		t_iterations := t_iterations + 1;
		EXIT WHEN t_rowsAdded = 0;
	END LOOP;

	CLUSTER ca_trust_purpose USING ctp_ca_tc_tp;

	RETURN t_iterations;
END;
$$ LANGUAGE plpgsql;
