CREATE OR REPLACE FUNCTION crl_update(
	_ca_id					crl.CA_ID%TYPE,
	_distribution_point_url	crl.DISTRIBUTION_POINT_URL%TYPE,
	_this_update			crl.THIS_UPDATE%TYPE,
	_next_update			crl.NEXT_UPDATE%TYPE,
	_last_checked			crl.LAST_CHECKED%TYPE,
	_error_message			crl.ERROR_MESSAGE%TYPE,
	_crl_sha256				crl.CRL_SHA256%TYPE,
	_crl_size				crl.CRL_SIZE%TYPE
) RETURNS void
AS $$
DECLARE
BEGIN
	INSERT INTO crl_revoked (
			CA_ID, SERIAL_NUMBER, REASON_CODE,
			REVOCATION_DATE, LAST_SEEN_CHECK_DATE
		)
		SELECT _ca_id, crit.SERIAL_NUMBER, min(crit.REASON_CODE),
				min(crit.REVOCATION_DATE), _last_checked
			FROM crl_revoked_import_temp crit
			GROUP BY crit.SERIAL_NUMBER
		ON CONFLICT ON CONSTRAINT crlr_pk
			DO UPDATE
			SET REASON_CODE = excluded.REASON_CODE,
				REVOCATION_DATE = excluded.REVOCATION_DATE,
				LAST_SEEN_CHECK_DATE = excluded.LAST_SEEN_CHECK_DATE;

	UPDATE crl
		SET THIS_UPDATE = _this_update,
			NEXT_UPDATE = _next_update,
			LAST_CHECKED = _last_checked,
			NEXT_CHECK_DUE = _last_checked + interval '4 hours',
			ERROR_MESSAGE = _error_message,
			CRL_SHA256 = _crl_sha256,
			CRL_SIZE = _crl_size
		WHERE CA_ID = _ca_id
			AND DISTRIBUTION_POINT_URL = _distribution_point_url;
END;
$$ LANGUAGE plpgsql;
