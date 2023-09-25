/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2023 Sectigo Limited
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

CREATE OR REPLACE FUNCTION cert_counter(
) RETURNS TRIGGER
AS $$
DECLARE
	t_lastCertificateID		ca.LAST_CERTIFICATE_ID%TYPE;
	t_notAfter				timestamp;
	t_countIndex			smallint	:= 1;	-- Certificate.
BEGIN
	IF TG_OP = 'UPDATE' THEN
		IF (old.ID != new.ID) OR (old.CERTIFICATE != new.CERTIFICATE) THEN
			RAISE EXCEPTION 'Sorry, ISSUER_CA_ID is the only "certificate" field that can be UPDATEd.';
		ELSIF old.ISSUER_CA_ID = new.ISSUER_CA_ID THEN
			RETURN new;
		END IF;
	ELSIF TG_OP != 'DELETE' THEN
		RAISE EXCEPTION 'Sorry, expecting UPDATE or DELETE.';
	END IF;

	SELECT coalesce(max(ca.LAST_CERTIFICATE_ID), 0)
		INTO t_lastCertificateID
		FROM ca;

	-- Lock all affected "ca" row(s) for UPDATE together, to avoid potentially deadlocking with cert_processor.
	PERFORM
		FROM ca
		WHERE ca.ID IN (old.ISSUER_CA_ID, coalesce(new.ISSUER_CA_ID, old.ISSUER_CA_ID))
		FOR UPDATE;

	t_notAfter := coalesce(x509_notAfter(coalesce(new.CERTIFICATE, old.CERTIFICATE)), 'infinity'::timestamp);

	IF x509_hasExtension(coalesce(new.CERTIFICATE, old.CERTIFICATE), '1.3.6.1.4.1.11129.2.4.3', TRUE) THEN
		t_countIndex := 2;		-- Precertificate (RFC6962).
	END IF;

	IF TG_OP = 'UPDATE' THEN
		UPDATE ca
			SET NUM_ISSUED[t_countIndex] = coalesce(NUM_ISSUED[t_countIndex], 0) + 1,
				NUM_EXPIRED[t_countIndex] = coalesce(NUM_EXPIRED[t_countIndex], 0) + CASE WHEN ((new.ID <= t_lastCertificateID) AND (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp))) THEN 1 ELSE 0 END,
				NEXT_NOT_AFTER = CASE WHEN (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp)) THEN NEXT_NOT_AFTER ELSE least(coalesce(NEXT_NOT_AFTER, 'infinity'::timestamp), t_notAfter) END,
				LAST_CERTIFICATE_ID = CASE WHEN t_lastCertificateID >= new.ID THEN greatest(LAST_CERTIFICATE_ID, new.ID) ELSE LAST_CERTIFICATE_ID END
			WHERE ID = new.ISSUER_CA_ID;

		UPDATE lint_cert_issue
			SET ISSUER_CA_ID = new.ISSUER_CA_ID
			WHERE CERTIFICATE_ID = new.ID;
	END IF;

	UPDATE ca
		SET NUM_ISSUED[t_countIndex] = coalesce(NUM_ISSUED[t_countIndex], 0) - 1,
			NUM_EXPIRED[t_countIndex] = coalesce(NUM_EXPIRED[t_countIndex], 0) - CASE WHEN ((old.ID <= t_lastCertificateID) AND (t_notAfter <= coalesce(LAST_NOT_AFTER, '-infinity'::timestamp))) THEN 1 ELSE 0 END
		WHERE ID = old.ISSUER_CA_ID;

	IF TG_OP = 'UPDATE' THEN
		RETURN new;
	ELSE
		RETURN old;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
