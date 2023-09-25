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

CREATE OR REPLACE FUNCTION process_expirations(
	_new_expirations		OUT	bigint,
	_cas_affected			OUT	bigint,
	_min_last_not_after		OUT	ca.NEXT_NOT_AFTER%TYPE
)
AS $$
DECLARE
	t_newExpirationsC		bigint;
	t_newExpirationsP		bigint;
	t_nextNotAfter_new		ca.NEXT_NOT_AFTER%TYPE;
	l_ca					RECORD;
BEGIN
	_new_expirations := 0;
	_cas_affected := 0;

	FOR l_ca IN (
		SELECT ca.ID, ca.NEXT_NOT_AFTER, coalesce(ca.LAST_NOT_AFTER, '-infinity'::timestamp) LAST_NOT_AFTER_OLD,
				least(date_trunc('second', now() AT TIME ZONE 'UTC') - interval '1 second', ca.NEXT_NOT_AFTER + interval '10 minutes') LAST_NOT_AFTER_NEW,
				ca.LAST_CERTIFICATE_ID
			FROM ca
			WHERE ca.NEXT_NOT_AFTER < date_trunc('second', now() AT TIME ZONE 'UTC')
			ORDER BY ca.NEXT_NOT_AFTER
			FOR UPDATE SKIP LOCKED
	) LOOP
		SELECT coalesce(sum(CASE WHEN is_precertificate THEN 0 ELSE 1 END), 0),
				coalesce(sum(CASE WHEN is_precertificate THEN 1 ELSE 0 END), 0)
			INTO t_newExpirationsC,
				t_newExpirationsP
			FROM certificate c
					INNER JOIN x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE) is_precertificate ON TRUE
			WHERE c.ISSUER_CA_ID = l_ca.ID
				AND c.ID <= l_ca.LAST_CERTIFICATE_ID
				AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > l_ca.LAST_NOT_AFTER_OLD
				AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) <= l_ca.LAST_NOT_AFTER_NEW;

		SELECT min(coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp))
			INTO t_nextNotAfter_new
			FROM certificate c
			WHERE c.ISSUER_CA_ID = l_ca.ID
				AND c.ID <= l_ca.LAST_CERTIFICATE_ID
				AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > l_ca.LAST_NOT_AFTER_NEW;

		UPDATE ca
			SET NUM_EXPIRED[1] = coalesce(ca.NUM_EXPIRED[1], 0) + t_newExpirationsC,
				NUM_EXPIRED[2] = coalesce(ca.NUM_EXPIRED[2], 0) + t_newExpirationsP,
				LAST_NOT_AFTER = l_ca.LAST_NOT_AFTER_NEW,
				NEXT_NOT_AFTER = t_nextNotAfter_new
			WHERE ca.ID = l_ca.ID;

		_new_expirations := _new_expirations + t_newExpirationsC + t_newExpirationsP;
		_cas_affected := _cas_affected + 1;
		_min_last_not_after := least(coalesce(_min_last_not_after, l_ca.LAST_NOT_AFTER_NEW), l_ca.LAST_NOT_AFTER_NEW);
	END LOOP;
END;
$$ LANGUAGE plpgsql;
