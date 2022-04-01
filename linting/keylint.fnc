CREATE OR REPLACE FUNCTION keylint(
	cert					bytea
) RETURNS SETOF text
AS $$
DECLARE
BEGIN
	IF x509_keyAlgorithm(cert) = 'RSA' THEN
		IF x509_hasROCAFingerprint(cert) THEN
			RETURN NEXT 'E: ROCA vulnerability';
		END IF;

		IF x509_hasClosePrimes(cert) THEN
			RETURN NEXT 'E: Close Primes vulnerability';
		END IF;

		PERFORM 1
			FROM debian_weak_key dwk
			WHERE dwk.SHA1_MODULUS = digest('Modulus=' || upper(encode(x509_rsaModulus(cert), 'hex')) || chr(10), 'sha1');
		IF FOUND THEN
			RETURN NEXT 'E: Debian OpenSSL RNG vulnerability';
		END IF;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
