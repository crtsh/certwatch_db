CREATE OR REPLACE FUNCTION certification_graph(
	cert_identifier			text,
	trust_context_id		trust_context.ID%TYPE	DEFAULT	0,
	trust_purpose_id		trust_purpose.ID%TYPE	DEFAULT	0
) RETURNS text
AS $$
DECLARE
	t_certificateID		certificate.ID%TYPE;
	t_spkiSHA256		bytea;
	t_source			text;
	t_target			text;
	t_label				text;
	t_colour			text;
	t_lineColour		text;
	t_shape				text;
	t_href				text;
	t_edges				text[];
	t_nodes				text[];
	l_record			RECORD;
BEGIN
	IF length(cert_identifier) = 64 THEN
		SELECT c.ID, digest(x509_publicKey(c.CERTIFICATE), 'sha256')
			INTO t_certificateID, t_spkiSHA256
			FROM certificate c
			WHERE digest(c.CERTIFICATE, 'sha256') = decode(cert_identifier, 'hex');
	ELSIF length(cert_identifier) = 40 THEN
		SELECT c.ID, digest(x509_publicKey(c.CERTIFICATE), 'sha256')
			INTO t_certificateID, t_spkiSHA256
			FROM certificate c
			WHERE digest(c.CERTIFICATE, 'sha1') = decode(cert_identifier, 'hex');
	ELSIF translate(cert_identifier, '0123456789', '') = '' THEN
		SELECT c.ID, digest(x509_publicKey(c.CERTIFICATE), 'sha256')
			INTO t_certificateID, t_spkiSHA256
			FROM certificate c
			WHERE c.ID = cert_identifier::bigint;
	END IF;
	IF t_certificateID IS NULL THEN
		RETURN NULL;
	END IF;

	FOR l_record IN (
		SELECT build_graph(t_certificateID, FALSE, trust_context_id, trust_purpose_id) as CHAIN
	) LOOP
		t_target := 'spkisha256= ' || substr(encode(t_spkiSHA256, 'hex'), 1, 8) || '...';
		t_shape := 'ellipse';
		FOR i IN 1..array_length(l_record.CHAIN, 1) LOOP
			t_source := ltrim(substring(l_record.CHAIN[i] from ':.*$'), ':');
			t_label := rtrim(substring(l_record.CHAIN[i] from '^.*:'), ':');
			IF t_source LIKE '%;%' THEN
				t_colour := ltrim(substring(t_source from ';.*$'), ';');
				IF t_colour = 'valid' THEN
					t_colour := '#22AA22';
					t_lineColour := '#77FF77';
				ELSIF t_colour = 'expired' THEN
					t_colour := '#AAAAAA';
					t_lineColour := '#DDDDDD';
				ELSIF t_colour = 'revoked' THEN
					t_colour := '#AA2222';
					t_lineColour := '#FF7777';
				ELSE
					t_colour := '#000000';
					t_lineColour := '#000000';
				END IF;
				t_source := rtrim(substring(t_source from '^.*;'), ';');
			END IF;
			t_edges := array_append(t_edges, '{"data":{"color":"' || t_colour || '","linecolor":"' || t_lineColour || '","source":"' || t_source || '","target":"' || t_target || '","label":"' || t_label || '","href":"?id=' || t_label || '"}}');
			IF t_target LIKE 'spkisha256=%' THEN
				t_label := t_target;
				t_href := '?spkisha256=' || encode(t_spkiSHA256, 'hex');
			ELSE
				t_label := get_ca_name_attribute(t_target::integer);
				t_href := '?caid=' || t_target::integer;
			END IF;
			t_nodes := array_append(t_nodes, '{"data":{"color":"' || t_colour || '","id":"' || t_target || '","label":"' || t_label || '","href":"' || t_href || '","type":"' || t_shape || '"}}');
			t_target := t_source;
			t_shape := 'barrel';
		END LOOP;
		IF t_target LIKE 'trust_%' THEN
			t_nodes := array_append(t_nodes, '{"data":{"color":"#7777FF","id":"' || t_target || '","label":"' || substr(t_target, 7) || '","type":"diamond"}}');
		END IF;
	END LOOP;

	RETURN
'[BEGIN_HEADERS]
Content-Type: application/json
[END_HEADERS]
{"elements":{"nodes":[' || array_to_string(ARRAY(SELECT DISTINCT UNNEST(t_nodes) ORDER BY 1), ',') || '],"edges":[' || array_to_string(ARRAY(SELECT DISTINCT UNNEST(t_edges) ORDER BY 1), ',') || ']}}';
END;
$$ LANGUAGE plpgsql;
