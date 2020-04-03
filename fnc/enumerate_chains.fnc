/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

CREATE OR REPLACE FUNCTION enumerate_chains(
	cert_id					certificate.ID%TYPE,
	must_be_time_valid		boolean					DEFAULT TRUE,
	trust_ctx_id			trust_context.ID%TYPE	DEFAULT NULL,
	trust_purp_id			trust_purpose.ID%TYPE	DEFAULT NULL,
	only_one_chain			boolean					DEFAULT FALSE,
	max_ca_repeats			integer					DEFAULT 0,
	certchain_so_far		bigint[]				DEFAULT NULL,
	cachain_so_far			integer[]				DEFAULT NULL
) RETURNS SETOF bigint[]
AS $$
DECLARE
	t_certificate		certificate.CERTIFICATE%TYPE;
	t_issuerCAID		certificate.ISSUER_CA_ID%TYPE;
	t_caID				ca.ID%TYPE;
	t_caChainSoFar		integer[];
	t_certChainSoFar	bigint[];
	l_issuer			RECORD;
	l_chain				RECORD;
	t_count				integer;
BEGIN
	SELECT c.CERTIFICATE, c.ISSUER_CA_ID
		INTO t_certificate, t_issuerCAID
		FROM certificate c
		WHERE c.ID = cert_id;
	IF t_certificate IS NULL THEN
		RETURN;
	END IF;

	IF trust_ctx_id IS NOT NULL THEN
		SELECT count(*)
			FROM root_trust_purpose rtp
			INTO t_count
			WHERE rtp.CERTIFICATE_ID = cert_id
				AND rtp.TRUST_CONTEXT_ID = trust_ctx_id
				AND rtp.TRUST_PURPOSE_ID = coalesce(trust_purp_id, rtp.TRUST_PURPOSE_ID);
		IF t_count > 0 THEN
			t_certChainSoFar := array_append(certchain_so_far, cert_id);
			RETURN NEXT t_certChainSoFar;
			RETURN;
		END IF;
	END IF;

	-- If this is a CA Certificate, check if the CA has already appeared in the
	-- chain.
	SELECT cac.CA_ID
		INTO t_caID
		FROM ca_certificate cac
		WHERE cac.CERTIFICATE_ID = cert_id;
	IF t_caID IS NOT NULL THEN
		IF t_caID = t_issuerCAID THEN
			-- Avoid untrusted, self-signed CA certificate loops!
			RETURN;
		ELSIF (cachain_so_far IS NOT NULL)
				AND (cachain_so_far @> ARRAY[t_caID]) THEN
			-- Avoid (too many) cross-certification loops!
			IF array_length(cachain_so_far, 1) - array_length(array_remove(cachain_so_far, t_caID), 1) > max_ca_repeats THEN
				RETURN;
			END IF;
		END IF;
		t_caChainSoFar := array_append(cachain_so_far, t_caID);
	END IF;

	-- Enforce any Basic Constraints pathLenConstraint in this certificate.
	IF (COALESCE(x509_getPathLenConstraint(t_certificate)::bigint,
					array_length(certchain_so_far, 1)) + 1)
			< array_length(certchain_so_far, 1) THEN
		RETURN;
	END IF;

	-- Enforce a maximum path length of 20 certificates.
	IF array_length(certchain_so_far, 1) >= 20 THEN
		-- Append -1 to show that the maximum length has been reached.
		RETURN NEXT array_append(certchain_so_far, -1);
		RETURN;
	END IF;

	-- Output this chain.
	t_certChainSoFar := array_append(certchain_so_far, cert_id);

	-- Loop through every matching issuer CA certificate.
	FOR l_issuer IN (
				SELECT cac.CERTIFICATE_ID, cac.CA_ID
					FROM certificate c, ca, ca_certificate cac
					WHERE c.ID = cert_id
						AND c.ISSUER_CA_ID = ca.ID
						AND ca.PUBLIC_KEY != E'\\x00'
						AND ca.ID = cac.CA_ID
					ORDER BY ca.ID DESC
			) LOOP
		IF (trust_ctx_id IS NOT NULL) OR (trust_purp_id IS NOT NULL) THEN
			SELECT COUNT(*)
				INTO t_count
				FROM ca_trust_purpose ctp
				WHERE ctp.CA_ID = l_issuer.CA_ID
					AND ctp.TRUST_CONTEXT_ID = COALESCE(trust_ctx_id,
														ctp.TRUST_CONTEXT_ID)
					AND ctp.TRUST_PURPOSE_ID = COALESCE(trust_purp_id,
														ctp.TRUST_PURPOSE_ID)
					AND ctp.IS_TIME_VALID >= COALESCE(must_be_time_valid, FALSE);
			IF (t_count > 0) AND (trust_purp_id >= 100) THEN	-- EV Server Authentication.
				-- EV Server Authentication must also be trusted for Server Authentication.
				SELECT COUNT(*)
					INTO t_count
					FROM ca_trust_purpose ctp
					WHERE ctp.CA_ID = l_issuer.CA_ID
						AND ctp.TRUST_CONTEXT_ID = COALESCE(trust_ctx_id,
															ctp.TRUST_CONTEXT_ID)
						AND ctp.TRUST_PURPOSE_ID IN (1, 30);	-- Server Authentication, SGC.
			END IF;
		ELSE
			t_count := 1;
		END IF;
		IF t_count > 0 THEN
			FOR l_chain IN (
						SELECT enumerate_chains(l_issuer.CERTIFICATE_ID, must_be_time_valid,
								trust_ctx_id, trust_purp_id, only_one_chain,
								max_ca_repeats, t_certChainSoFar, t_caChainSoFar)
					) LOOP
				RETURN NEXT l_chain.enumerate_chains;
				IF only_one_chain THEN
					RETURN;
				END IF;
			END LOOP;
		END IF;
	END LOOP;
END;
$$ LANGUAGE plpgsql;
