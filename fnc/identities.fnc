CREATE OR REPLACE FUNCTION identities(
	cert					bytea,
	is_subject				boolean		DEFAULT true
) RETURNS tsvector
AS $$
DECLARE
	t_string				text := '';
	t_position				integer;
	l_identity				RECORD;
BEGIN
	FOR l_identity IN (
		SELECT sub.VALUE,
				CASE WHEN sub.TYPE IN ('2.5.4.3', 'type2') THEN substring(sub.VALUE FROM position('.' IN (sub.VALUE || '.')) + 1)		-- commonName, dNSName.
					WHEN sub.TYPE IN ('1.2.840.113549.1.9.1', 'type1') THEN substring(sub.VALUE FROM position('@' IN sub.VALUE) + 1)	-- emailAddress, rfc822Name.
				END AS DOMAIN_NAME
			FROM (
				SELECT encode(RAW_VALUE, 'escape') AS VALUE,
						ATTRIBUTE_OID AS TYPE
					FROM public.x509_nameAttributes_raw(cert, is_subject)
				UNION
				SELECT encode(RAW_VALUE, 'escape') AS VALUE,
						('type' || TYPE_NUM::text) AS TYPE
					FROM public.x509_altNames_raw(cert, is_subject)
			) sub
			GROUP BY sub.VALUE, DOMAIN_NAME
	) LOOP
		t_string := t_string || ' ' || l_identity.VALUE;
		IF coalesce(l_identity.DOMAIN_NAME, '') != '' THEN
			LOOP
				t_string := t_string || ' ' || l_identity.DOMAIN_NAME;
				t_position := coalesce(position('.' IN l_identity.DOMAIN_NAME), 0);
				EXIT WHEN t_position = 0;
				l_identity.DOMAIN_NAME := substring(l_identity.DOMAIN_NAME FROM (t_position + 1));
			END LOOP;
		END IF;
	END LOOP;

	RETURN strip(to_tsvector(ltrim(t_string)));
END;
$$ LANGUAGE plpgsql STRICT IMMUTABLE;
