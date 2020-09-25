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

CREATE OR REPLACE FUNCTION lint_tbscertificate(
	tbscert					bytea
) RETURNS text
AS $$
DECLARE
	t_certificate			bytea;
	t_header				text;
	t_sigHashAlg			text;
	t_output				text := '';
	l_linter				RECORD;
BEGIN
	-- Add ASN.1 packaging and a dummy signature to create a "valid" X.509
	-- certificate that x509_print() can process.
	t_certificate := tbscert || E'\\x3003060100030100';
	t_header := to_hex(length(t_certificate));
	IF length(t_header) % 2 > 0 THEN
		t_header := '0' || t_header;
	END IF;
	IF length(t_header) > 2 THEN
		t_header := to_hex(128 + (length(t_header) / 2)) || t_header;
	END IF;
	t_certificate := E'\\x30' || decode(t_header, 'hex') || t_certificate;

	-- cablint checks that an ECDSA signature has a syntactically valid ECDSA-Sig-Value structure (that is, a SEQUENCE containing two INTEGERs), and exits early with a FATAL error if not.
	-- ZLint checks that an ECDSA signature has roughly the expected length, based on the assumption that ecdsa-with-SHA256 implies a P-256 signing key, and that ecdsa-with-SHA384 implies a P-384 signing key.
	-- ZLint and x509lint both check that the "inner" and "outer" signature algorithm identifiers match.
	-- So we need to manufacture fake signatures that satisfy these syntax checks.
	t_sigHashAlg := substring(x509_print(t_certificate), 'Signature Algorithm: (.*?)\n');
	IF t_sigHashAlg IS NULL THEN
		RETURN NULL;
	ELSIF t_sigHashAlg = 'sha1WithRSAEncryption' THEN
		t_certificate := tbscert || E'\\x300D06092A864886F70D0101050500030100';
	ELSIF t_sigHashAlg = 'sha256WithRSAEncryption' THEN
		t_certificate := tbscert || E'\\x300D06092A864886F70D01010b0500030100';
	ELSIF t_sigHashAlg = 'sha384WithRSAEncryption' THEN
		t_certificate := tbscert || E'\\x300D06092A864886F70D01010c0500030100';
	ELSIF t_sigHashAlg = 'sha512WithRSAEncryption' THEN
		t_certificate := tbscert || E'\\x300D06092A864886F70D01010d0500030100';
	ELSIF t_sigHashAlg = 'ecdsa-with-SHA256' THEN
		t_certificate := tbscert || E'\\x300A06082A8648CE3D040302034900304602210123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0102210123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01';
	ELSIF t_sigHashAlg = 'ecdsa-with-SHA384' THEN
		t_certificate := tbscert || E'\\x300A06082A8648CE3D040303036900306602310123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0102310123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01';
	END IF;

	t_header := to_hex(length(t_certificate));
	IF length(t_header) % 2 > 0 THEN
		t_header := '0' || t_header;
	END IF;
	IF length(t_header) > 2 THEN
		t_header := to_hex(128 + (length(t_header) / 2)) || t_header;
	END IF;

	RETURN lint_certificate(E'\\x30' || decode(t_header, 'hex') || t_certificate, TRUE);
END;
$$ LANGUAGE plpgsql STRICT;
