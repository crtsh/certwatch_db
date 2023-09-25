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

CREATE OR REPLACE FUNCTION process_cert_urls(
) RETURNS void
AS $$
BEGIN
	-- Add records for any newly encountered CRL Distribution Point URLs.
	INSERT INTO crl ( CA_ID, DISTRIBUTION_POINT_URL, NEXT_CHECK_DUE, FIRST_CERTIFICATE_ID, IS_ACTIVE )
		SELECT icut.CA_ID, icut.URL, now() AT TIME ZONE 'UTC', icut.FIRST_CERTIFICATE_ID, TRUE
			FROM importcerturls_temp icut
			WHERE icut.URL_TYPE = 0
		ON CONFLICT ON CONSTRAINT crl_pk
			DO UPDATE SET FIRST_CERTIFICATE_ID = least(crl.FIRST_CERTIFICATE_ID, excluded.FIRST_CERTIFICATE_ID);

	-- Add records for any newly encountered OCSP Responder URLs, respecting ors.IGNORE_OTHER_URLS.
	INSERT INTO ocsp_responder ( CA_ID, URL, NEXT_CHECKS_DUE, FIRST_CERTIFICATE_ID )
		SELECT icut.CA_ID, icut.URL, now() AT TIME ZONE 'UTC', icut.FIRST_CERTIFICATE_ID
			FROM importcerturls_temp icut
			WHERE icut.URL_TYPE = 1
				AND NOT EXISTS (
					SELECT 1
						FROM ocsp_responder ors
						WHERE ors.CA_ID = icut.CA_ID
							AND ors.IGNORE_OTHER_URLS
				)
		ON CONFLICT ON CONSTRAINT or_pk
			DO UPDATE SET FIRST_CERTIFICATE_ID = least(ocsp_responder.FIRST_CERTIFICATE_ID, excluded.FIRST_CERTIFICATE_ID);

	-- Add records for any newly encountered CA Issuers URLs.
	INSERT INTO ca_issuer ( CA_ID, URL, NEXT_CHECK_DUE, FIRST_CERTIFICATE_ID, IS_ACTIVE )
		SELECT icut.CA_ID, icut.URL, now() AT TIME ZONE 'UTC', icut.FIRST_CERTIFICATE_ID, TRUE
			FROM importcerturls_temp icut
			WHERE icut.URL_TYPE = 2
		ON CONFLICT ON CONSTRAINT cais_pk
			DO UPDATE SET FIRST_CERTIFICATE_ID = least(ca_issuer.FIRST_CERTIFICATE_ID, excluded.FIRST_CERTIFICATE_ID);
END;
$$ LANGUAGE plpgsql;
