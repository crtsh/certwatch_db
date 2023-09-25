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

CREATE OR REPLACE FUNCTION import_leaf_certs(
) RETURNS TABLE(CERTIFICATE_ID bigint, SHA256_CERT bytea)
AS $$
BEGIN
	-- Determine which (pre)certificates are already known.
	-- Optimization: Compare x509_notAfter() to avoid wasting time checking the wrong "certificate" partitions.
	UPDATE importleafcerts_temp ilct
		SET CERTIFICATE_ID = c.ID,
			IS_NEW_CERT = 'f'
		FROM certificate c
		WHERE ilct.SHA256_X509 = digest(c.CERTIFICATE, 'sha256')
			AND coalesce(x509_notAfter(ilct.DER_X509), 'infinity'::timestamp) = coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp);

	-- Assign IDs for the (pre)certificates that are new.
	UPDATE importleafcerts_temp ilct
		SET CERTIFICATE_ID = nextval('certificate_id_seq'::regclass)
		WHERE ilct.IS_NEW_CERT;

	-- Insert the new (pre)certificates, using libx509pq/OpenSSL to attempt to determine the CA IDs for any new leaf (pre)certificates that the ct_monitor Go code could not.
	INSERT INTO certificate ( ID, ISSUER_CA_ID, CERTIFICATE )
		SELECT ilct.CERTIFICATE_ID, coalesce(ilct.ISSUER_CA_ID, find_issuer(ilct.DER_X509)), ilct.DER_X509
			FROM importleafcerts_temp ilct
			WHERE ilct.IS_NEW_CERT;

	-- Return all (new and existing) of the leaf (pre)certificate IDs and SHA-256 fingerprints.
	RETURN QUERY
	SELECT ilct.CERTIFICATE_ID, ilct.SHA256_X509
		FROM importleafcerts_temp ilct;
END;
$$ LANGUAGE plpgsql;
