CREATE OR REPLACE FUNCTION pem_cert(
	certificate				certificate.CERTIFICATE%TYPE
) RETURNS text
AS $$
DECLARE
	t_b64Certificate	text;
	t_output			text	:= '';
BEGIN
	t_b64Certificate := replace(encode(certificate, 'base64'), chr(10), '');

	WHILE length(t_b64Certificate) > 64 LOOP
		t_output := t_output || substring(
			t_b64Certificate from 1 for 64
		) || chr(10);
		t_b64Certificate := substring(t_b64Certificate from 65);
	END LOOP;
	IF coalesce(t_b64Certificate, '') != '' THEN
		t_output := t_output || t_b64Certificate || chr(10);
	END IF;

	RETURN '-----BEGIN CERTIFICATE-----' || chr(10) || t_output || '-----END CERTIFICATE-----' || chr(10);
END;
$$ LANGUAGE plpgsql;
