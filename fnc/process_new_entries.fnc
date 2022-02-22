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

CREATE OR REPLACE FUNCTION process_new_entries(
) RETURNS void
AS $$
DECLARE
	caCert_cursor		CURSOR FOR
							SELECT x509_subjectName(net.DER_X509) SUBJECT_NAME,
									x509_publicKey(net.DER_X509) PUBLIC_KEY
								FROM newentries_temp net
								WHERE net.NEW_AND_CAN_ISSUE_CERTS
								FOR UPDATE;
	findIssuer_cursor	CURSOR FOR
							SELECT net.CT_LOG_ID, net.ENTRY_ID, net.ENTRY_TIMESTAMP,
									net.DER_X509, net.CERTIFICATE_ID,
									net.ISSUER_CA_ID, NULL::boolean LINTING_APPLIES,
									net.NEW_AND_CAN_ISSUE_CERTS
								FROM newentries_temp net
								WHERE net.NUM_ISSUED_INDEX > 0
									AND net.ISSUER_CA_ID IS NULL
								FOR UPDATE;

	t_caID				ca.ID%TYPE;
	l_ca				RECORD;
	t_isNewCA			boolean;
BEGIN
	-- Linting requirements flow down from the issuer CA.
	UPDATE newentries_temp net
		SET LINTING_APPLIES = 't'
		FROM ca
		WHERE net.ISSUER_CA_ID IS NOT NULL
			AND net.ISSUER_CA_ID = ca.ID
			AND ca.LINTING_APPLIES = 't';

	-- Determine which certificates are already known.
	-- Optimization: Compare x509_notAfter() to avoid wasting time checking the wrong "certificate" partitions.
	UPDATE newentries_temp net
		SET CERTIFICATE_ID = c.ID,
			NUM_ISSUED_INDEX = 0
		FROM certificate c
		WHERE net.SHA256_X509 = digest(c.CERTIFICATE, 'sha256')
			AND coalesce(x509_notAfter(net.DER_X509), 'infinity'::timestamp) = coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp);

	-- Assign IDs for the certificates that are new.
	UPDATE newentries_temp net
		SET CERTIFICATE_ID = sub.NEW_CERTIFICATE_ID,
			NEW_AND_CAN_ISSUE_CERTS = x509_canIssueCerts(net.DER_X509)
		FROM (
				SELECT net2.SHA256_X509,
						nextval('certificate_id_seq'::regclass) NEW_CERTIFICATE_ID
					FROM newentries_temp net2
					WHERE net2.NUM_ISSUED_INDEX > 0
					GROUP BY net2.SHA256_X509
			) sub
		WHERE net.SHA256_X509 = sub.SHA256_X509;

	-- If this is a CA certificate, find (or create) the Subject CA record.
	FOR l_caCert IN caCert_cursor LOOP
		IF l_caCert.PUBLIC_KEY IS NULL THEN
			l_caCert.PUBLIC_KEY := E'\\x00';
		END IF;

		t_isNewCA := FALSE;
		SELECT ca.ID
			INTO t_caID
			FROM ca
			WHERE ca.NAME = l_caCert.SUBJECT_NAME
				AND ca.PUBLIC_KEY IN (l_caCert.PUBLIC_KEY, E'\\x00');
		IF t_caID IS NULL THEN
			INSERT INTO ca (
					NAME, PUBLIC_KEY, LINTING_APPLIES
				)
				VALUES (
					l_caCert.SUBJECT_NAME, l_caCert.PUBLIC_KEY, 't'
				)
				RETURNING ca.ID
					INTO t_caID;
			t_isNewCA := TRUE;
		END IF;
		UPDATE newentries_temp
			SET SUBJECT_CA_ID = t_caID,
				IS_NEW_CA = t_isNewCA
			WHERE CURRENT OF caCert_cursor;
	END LOOP;

	FOR l_entry IN findIssuer_cursor LOOP
		-- The ct_monitor Go code was unable to determine the CA ID.
		-- Have another go, just in case libx509pq/OpenSSL can do better.
		FOR l_ca IN (
			SELECT ca.ID, ca.LINTING_APPLIES, ca.PUBLIC_KEY
				FROM ca
				WHERE ca.NAME = x509_issuerName(l_entry.DER_X509)
					AND ca.PUBLIC_KEY != E'\\x00'
				ORDER BY octet_length(ca.PUBLIC_KEY) DESC
		) LOOP
			IF x509_verify(l_entry.DER_X509, l_ca.PUBLIC_KEY) THEN
				l_entry.ISSUER_CA_ID := l_ca.ID;
				l_entry.LINTING_APPLIES := l_ca.LINTING_APPLIES;
				EXIT;
			END IF;
		END LOOP;

		UPDATE newentries_temp net
			SET ISSUER_CA_ID = coalesce(l_entry.ISSUER_CA_ID, -1),
				LINTING_APPLIES = coalesce(l_entry.LINTING_APPLIES, 't')
			WHERE CURRENT OF findIssuer_cursor;
	END LOOP;

	INSERT INTO certificate (
			ID, ISSUER_CA_ID, CERTIFICATE
		)
		SELECT net.CERTIFICATE_ID, net.ISSUER_CA_ID, net.DER_X509
			FROM newentries_temp net
			WHERE net.NUM_ISSUED_INDEX > 0
			GROUP BY net.CERTIFICATE_ID, net.ISSUER_CA_ID, net.DER_X509;

	INSERT INTO ca_certificate (
			CERTIFICATE_ID, CA_ID
		)
		SELECT net.CERTIFICATE_ID, net.SUBJECT_CA_ID
			FROM newentries_temp net
			WHERE net.NEW_AND_CAN_ISSUE_CERTS;

	INSERT INTO ct_log_entry (
			CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID, ENTRY_TIMESTAMP
		)
		SELECT net.CERTIFICATE_ID, net.CT_LOG_ID, net.ENTRY_ID, net.ENTRY_TIMESTAMP
			FROM newentries_temp net;

	UPDATE ca
		SET LINTING_APPLIES = 'f'
		FROM newentries_temp net
		WHERE net.IS_NEW_CA
			AND NOT net.LINTING_APPLIES
			AND net.SUBJECT_CA_ID = ca.ID;

	UPDATE ca
		SET NUM_ISSUED[1] = coalesce(NUM_ISSUED[1], 0) + sub.CERTS_ISSUED,
			NUM_ISSUED[2] = coalesce(NUM_ISSUED[2], 0) + sub.PRECERTS_ISSUED,
			NUM_EXPIRED[1] = coalesce(NUM_EXPIRED[1], 0) + sub.CERTS_EXPIRED,
			NUM_EXPIRED[2] = coalesce(NUM_EXPIRED[2], 0) + sub.PRECERTS_EXPIRED,
			NEXT_NOT_AFTER = sub.NEXT_NOT_AFTER
		FROM (
			SELECT net.ISSUER_CA_ID,
					sum(CASE WHEN net.NUM_ISSUED_INDEX = 1 THEN 1 ELSE 0 END) CERTS_ISSUED,
					sum(CASE WHEN net.NUM_ISSUED_INDEX = 2 THEN 1 ELSE 0 END) PRECERTS_ISSUED,
					sum(CASE WHEN (net.NUM_ISSUED_INDEX = 1) AND (coalesce(x509_notAfter(net.DER_X509), 'infinity'::timestamp) <= coalesce(ca.LAST_NOT_AFTER, '-infinity'::timestamp)) THEN 1 ELSE 0 END) CERTS_EXPIRED,
					sum(CASE WHEN (net.NUM_ISSUED_INDEX = 2) AND (coalesce(x509_notAfter(net.DER_X509), 'infinity'::timestamp) <= coalesce(ca.LAST_NOT_AFTER, '-infinity'::timestamp)) THEN 1 ELSE 0 END) PRECERTS_EXPIRED,
					min(CASE WHEN (coalesce(x509_notAfter(net.DER_X509), 'infinity'::timestamp) <= coalesce(ca.LAST_NOT_AFTER, '-infinity'::timestamp)) THEN ca.NEXT_NOT_AFTER ELSE least(coalesce(ca.NEXT_NOT_AFTER, 'infinity'::timestamp), coalesce(x509_notAfter(net.DER_X509), 'infinity'::timestamp)) END) NEXT_NOT_AFTER
				FROM newentries_temp net, ca
				WHERE net.ISSUER_CA_ID = ca.ID
					AND net.NUM_ISSUED_INDEX > 0
				GROUP BY net.ISSUER_CA_ID
			) sub
		WHERE ca.ID = sub.ISSUER_CA_ID;

	INSERT INTO crl (
			CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, IS_ACTIVE
		)
		SELECT sub.ISSUER_CA_ID, sub.DISTRIBUTION_POINT_URL, now() AT TIME ZONE 'UTC', TRUE
			FROM (
					SELECT net.ISSUER_CA_ID, trim(x509_crlDistributionPoints(net.DER_X509)) DISTRIBUTION_POINT_URL
						FROM newentries_temp net
						WHERE net.NUM_ISSUED_INDEX > 0
						GROUP BY net.ISSUER_CA_ID, DISTRIBUTION_POINT_URL
				) sub
			WHERE NOT EXISTS (
				SELECT 1
					FROM crl
					WHERE crl.CA_ID = sub.ISSUER_CA_ID
						AND crl.DISTRIBUTION_POINT_URL = sub.DISTRIBUTION_POINT_URL
			);

	INSERT INTO ocsp_responder (
			CA_ID, URL, NEXT_CHECKS_DUE
		)
		SELECT sub.ISSUER_CA_ID, sub.URL, now() AT TIME ZONE 'UTC'
			FROM (
					SELECT net.ISSUER_CA_ID, trim(x509_authorityInfoAccess(net.DER_X509, 1)) URL
						FROM newentries_temp net
						WHERE net.NUM_ISSUED_INDEX > 0
						GROUP BY net.ISSUER_CA_ID, URL
				) sub
			WHERE NOT EXISTS (
				SELECT 1
					FROM ocsp_responder ors
					WHERE ors.CA_ID = sub.ISSUER_CA_ID
						AND (
							ors.URL = sub.URL
							OR ors.IGNORE_OTHER_URLS
						)
			);

	INSERT INTO ca_issuer (
			CA_ID, URL, NEXT_CHECK_DUE, FIRST_CERTIFICATE_ID, IS_ACTIVE
		)
		SELECT sub.ISSUER_CA_ID, sub.URL, now() AT TIME ZONE 'UTC', sub.FIRST_CERTIFICATE_ID, TRUE
			FROM (
					SELECT net.ISSUER_CA_ID, trim(x509_authorityInfoAccess(net.DER_X509, 2)) URL, min(net.CERTIFICATE_ID) FIRST_CERTIFICATE_ID
						FROM newentries_temp net
						WHERE net.NUM_ISSUED_INDEX > 0
						GROUP BY net.ISSUER_CA_ID, URL
				) sub
			WHERE NOT EXISTS (
				SELECT 1
					FROM ca_issuer cais
					WHERE cais.CA_ID = sub.ISSUER_CA_ID
						AND cais.URL = sub.URL
			);
END;
$$ LANGUAGE plpgsql;
