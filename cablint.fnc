CREATE OR REPLACE FUNCTION cablint(cert_data bytea) RETURNS text
LANGUAGE plsh
AS $$
#!/bin/sh
echo "$1" | xxd -r -ps | ruby -I /usr/local/certlint/lib /usr/local/bin/cablint /dev/stdin
$$;
