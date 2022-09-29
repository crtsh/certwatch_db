CREATE OR REPLACE FUNCTION pki_hierarchy(
	cert_id					certificate.ID%TYPE,
	exclude_expired			boolean					DEFAULT FALSE,
	trust_ctx_id			trust_context.ID%TYPE	DEFAULT	NULL,
	trust_purp_id			trust_purpose.ID%TYPE	DEFAULT	NULL,
	path_len_constraint		integer					DEFAULT NULL,
	ignore_cert_ids			bigint[]				DEFAULT NULL
) RETURNS text
AS $$
DECLARE
	t_caID				ca.ID%TYPE;
	t_thisOwner			text;
	t_parentOwner		text;
	t_certs				text		:= '';
	t_crossCerts		text		:= '';
	t_subCACerts		text		:= '';
	t_temp				text;
	t_temp2				text		:= '';
	t_backgroundColour	text;
	t_style				text;
	t_pathLenConstraint	integer;
	t_isCrossCert		boolean;
	t_isRecursionNeeded	boolean;
	l_certificate		RECORD;
BEGIN
	SELECT cac.CA_ID, coalesce(nullif(cc.SUBORDINATE_CA_OWNER, ''), nullif(cc.INCLUDED_CERTIFICATE_OWNER, ''))
		INTO t_caID, t_thisOwner
		FROM ca_certificate cac
				LEFT OUTER JOIN ccadb_certificate cc ON (cac.CERTIFICATE_ID = cc.CERTIFICATE_ID)
		WHERE cac.CERTIFICATE_ID = cert_id;
	IF t_thisOwner IS NULL THEN
		SELECT coalesce(nullif(cc.SUBORDINATE_CA_OWNER, ''), nullif(cc.INCLUDED_CERTIFICATE_OWNER, ''))
			INTO t_thisOwner
			FROM ca_certificate cac, certificate c, ccadb_certificate cc
			WHERE cac.CA_ID = t_caID
				AND cac.CERTIFICATE_ID = c.ID
				AND c.ID = cc.CERTIFICATE_ID
				AND cc.CCADB_RECORD_ID IS NOT NULL;
	END IF;

	IF ignore_cert_ids IS NULL THEN
		FOR l_certificate IN (
			SELECT c.ID, c.ISSUER_CA_ID,
					x509_getPathLenConstraint(c.CERTIFICATE) PATH_LEN_CONSTRAINT,
					x509_notAfter(c.CERTIFICATE) NOT_AFTER,
					x509_serialNumber(c.CERTIFICATE) SERIAL_NUMBER,
					get_ca_name_attribute(c.ISSUER_CA_ID) FRIENDLY_NAME
				FROM ca_certificate cac, certificate c
				WHERE cac.CA_ID = t_caID
					AND cac.CERTIFICATE_ID = c.ID
				ORDER BY FRIENDLY_NAME, NOT_AFTER DESC
		) LOOP
			IF exclude_expired AND l_certificate.NOT_AFTER < now() AT TIME ZONE 'UTC' THEN
				CONTINUE;
			END IF;

			SELECT array_to_string(array_agg(DISTINCT coalesce(coalesce(nullif(cc.SUBORDINATE_CA_OWNER, ''), nullif(cc.INCLUDED_CERTIFICATE_OWNER, '')), '?')), ' or ')
				INTO t_parentOwner
				FROM ca_certificate cac, certificate c, ccadb_certificate cc
				WHERE cac.CA_ID = l_certificate.ISSUER_CA_ID
					AND cac.CERTIFICATE_ID = c.ID
					AND c.ID = cc.CERTIFICATE_ID
					AND cc.CCADB_RECORD_ID IS NOT NULL;

			PERFORM
				FROM crl_revoked cr
				WHERE cr.CA_ID = l_certificate.ISSUER_CA_ID
					AND cr.SERIAL_NUMBER = l_certificate.SERIAL_NUMBER;
			IF FOUND THEN
				IF l_certificate.NOT_AFTER >= now() AT TIME ZONE 'UTC' THEN
					t_style := 'color:#CC0000;font-style:italic;text-decoration:line-through';
				ELSE
					t_style := 'color:#888888;font-style:italic;text-decoration:line-through';
				END IF;
			ELSIF l_certificate.NOT_AFTER < now() AT TIME ZONE 'UTC' THEN
				t_style := 'color:#888888';
			ELSIF t_backgroundColour IS NULL THEN
				t_style := 'color:#00CC00';
			ELSE
				t_style := 'color:#008800';
			END IF;

			t_temp := '<LI>';
			IF coalesce(t_thisOwner, '') != coalesce(t_parentOwner, '') THEN
				t_temp := t_temp || '<FONT style="color:#00007F"><B>[' || coalesce(t_parentOwner, '?');
				IF coalesce(t_parentOwner, '') LIKE '% or %' THEN
					t_temp := t_temp || '?';
				END IF;
				t_temp := t_temp || ']</B></FONT> ';
			END IF;
			t_temp := t_temp || '<A style="' || t_style || '" href="/?h=' || l_certificate.ID::text || '&opt=nometadata">' || l_certificate.ID::text || '</A> by '
							|| '<A href="/?caid=' || l_certificate.ISSUER_CA_ID::text || '">' || l_certificate.FRIENDLY_NAME
							|| '</A>&nbsp; <SPAN class="small">notAfter=' || l_certificate.NOT_AFTER::date || '&nbsp; pathLenConstraint=';
			IF coalesce(t_pathLenConstraint, 1048576) > 1000000 THEN
				t_temp := t_temp || 'unlimited';
			ELSE
				t_temp := t_temp || t_pathLenConstraint::text;
			END IF;
			t_temp := t_temp || '</SPAN></LI>
';

			t_certs := t_certs || t_temp;
		END LOOP;
	END IF;

	FOR l_certificate IN (
		WITH child_certificate AS MATERIALIZED (
			SELECT c.ID,
					x509_getPathLenConstraint(c.CERTIFICATE) PATH_LEN_CONSTRAINT,
					x509_notAfter(c.CERTIFICATE) NOT_AFTER,
					x509_serialNumber(c.CERTIFICATE) SERIAL_NUMBER,
					nullif(cc.INCLUDED_CERTIFICATE_OWNER, '') INCLUDED_CERTIFICATE_OWNER,
					nullif(cc.SUBORDINATE_CA_OWNER, '') SUBORDINATE_CA_OWNER
				FROM certificate c
						LEFT OUTER JOIN ccadb_certificate cc ON (c.ID = cc.CERTIFICATE_ID)
				WHERE c.ISSUER_CA_ID = t_caID
					AND x509_canIssueCerts(c.CERTIFICATE)
		)
		SELECT ch.ID,
				ch.PATH_LEN_CONSTRAINT,
				ch.NOT_AFTER,
				ch.SERIAL_NUMBER,
				ch.INCLUDED_CERTIFICATE_OWNER,
				ch.SUBORDINATE_CA_OWNER,
				cac.CA_ID,
				get_ca_name_attribute(cac.CA_ID) FRIENDLY_NAME
			FROM child_certificate ch,
				ca_certificate cac
			WHERE ch.ID = cac.CERTIFICATE_ID
				AND cac.CA_ID != t_caID
			GROUP BY ch.ID, ch.PATH_LEN_CONSTRAINT, ch.NOT_AFTER, ch.SERIAL_NUMBER, ch.INCLUDED_CERTIFICATE_OWNER, ch.SUBORDINATE_CA_OWNER, cac.CA_ID, get_ca_name_attribute(cac.CA_ID)
			ORDER BY get_ca_name_attribute(cac.CA_ID), ch.NOT_AFTER DESC
	) LOOP
		IF exclude_expired AND l_certificate.NOT_AFTER < now() AT TIME ZONE 'UTC' THEN
			CONTINUE;
		END IF;

		t_isCrossCert := FALSE;
		t_isRecursionNeeded := FALSE;
		t_pathLenConstraint := LEAST(coalesce(path_len_constraint, 1048576), coalesce(l_certificate.PATH_LEN_CONSTRAINT, 1048576));
		IF t_pathLenConstraint > 0 THEN
			IF NOT ((ignore_cert_ids IS NOT NULL) AND (ignore_cert_ids @> ARRAY[l_certificate.ID])) THEN
				PERFORM
					FROM ca_certificate cac, certificate c
					WHERE cac.CA_ID = l_certificate.CA_ID
						AND cac.CERTIFICATE_ID = c.ID
						AND c.ISSUER_CA_ID = cac.CA_ID;
				IF FOUND THEN
					t_isCrossCert := TRUE;
				ELSE
					t_isRecursionNeeded := TRUE;
				END IF;
			END IF;
		END IF;

		PERFORM
			FROM crl_revoked cr
			WHERE cr.CA_ID = t_caID
				AND cr.SERIAL_NUMBER = l_certificate.SERIAL_NUMBER;
		IF FOUND THEN
			IF l_certificate.NOT_AFTER >= now() AT TIME ZONE 'UTC' THEN
				t_style := 'color:#CC0000;font-style:italic;text-decoration:line-through';
			ELSE
				t_style := 'color:#888888;font-style:italic;text-decoration:line-through';
			END IF;
		ELSIF l_certificate.NOT_AFTER < now() AT TIME ZONE 'UTC' THEN
			t_style := 'color:#888888';
		ELSIF t_backgroundColour IS NULL THEN
			t_style := 'color:#00CC00';
		ELSE
			t_style := 'color:#008800';
		END IF;

		t_temp := '<LI>';
		IF coalesce(l_certificate.INCLUDED_CERTIFICATE_OWNER, '') != coalesce(coalesce(l_certificate.SUBORDINATE_CA_OWNER, l_certificate.INCLUDED_CERTIFICATE_OWNER), '') THEN
			t_temp := t_temp || '<FONT style="color:#00007F"><B>[' || l_certificate.SUBORDINATE_CA_OWNER || ']</B></FONT> ';
		END IF;

		t_temp := t_temp || '<A style="' || t_style || '" href="/?h=' || l_certificate.ID || '&opt=nometadata">' || l_certificate.ID::text || '</A> to <A href="/?caid=' || l_certificate.CA_ID::text || '">' || l_certificate.FRIENDLY_NAME || '</A>&nbsp; <SPAN class="small">notAfter=' || l_certificate.NOT_AFTER::date || '</SPAN>';

		IF t_isRecursionNeeded THEN
			t_temp := t_temp || '&nbsp; <SPAN class="small">pathLenConstraint=';
			IF t_pathLenConstraint > 1000000 THEN
				t_temp := t_temp || 'unlimited';
			ELSE
				t_temp := t_temp || t_pathLenConstraint::text;
			END IF;
			t_temp := t_temp || '</SPAN>' || pki_hierarchy(l_certificate.ID, exclude_expired, trust_ctx_id, trust_purp_id, t_pathLenConstraint - 1, array_append(ignore_cert_ids, l_certificate.ID));
		END IF;

		t_temp := t_temp || '</LI>
';
		IF t_isCrossCert THEN
			t_crossCerts := t_crossCerts || t_temp;
		ELSE
			t_subCACerts := t_subCACerts || t_temp;
		END IF;
	END LOOP;

	IF t_certs = '' THEN
		IF ignore_cert_ids IS NULL THEN
			t_certs := '<BR><FONT style="color:#CCCCCC"><I>None found</I></FONT><BR>';
		END IF;
	ELSE
		t_certs := '<UL style="margin-top:0px;margin-bottom:0px">' || t_certs || '</UL>';
	END IF;

	IF t_crossCerts = '' THEN
		IF ignore_cert_ids IS NULL THEN
			t_crossCerts := '<BR><FONT style="color:#CCCCCC"><I>None found</I></FONT><BR>';
		END IF;
	ELSE
		t_crossCerts := '<UL style="margin-top:0px;margin-bottom:0px">' || t_crossCerts || '</UL>';
	END IF;

	IF t_subCACerts = '' THEN
		IF ignore_cert_ids IS NULL THEN
			t_subCACerts := '<BR><FONT style="color:#CCCCCC"><I>None found</I></FONT>';
		END IF;
	ELSE
		t_subCACerts := '<UL style="margin-top:0px;margin-bottom:0px">' || t_subCACerts || '</UL>';
	END IF;

	IF ignore_cert_ids IS NULL THEN
		t_temp := get_ca_name_attribute(t_caID);
		IF exclude_expired THEN
			t_temp2 := 'Unexpired ';
		END IF;
		RETURN t_temp2 || '<B>Certificates</B> issued to <A href="?caid=' || t_caID || '">' || t_temp || '</A>:' || t_certs
				|| '<BR>' || t_temp2 || '<B>Cross Certificates</B> issued by <A href="?caid=' || t_caID || '">' || t_temp || '</A>:' || t_crossCerts
				|| '<BR>' || t_temp2 || '<B>Subordinate CA Certificates</B> issued by <A href="?caid=' || t_caID || '">' || t_temp || '</A>:' || t_subCACerts;
	ELSE
		RETURN t_certs || t_crossCerts || t_subCACerts;
	END IF;
END;
$$ LANGUAGE plpgsql;
