CREATE OR REPLACE FUNCTION update_expirations(
	ca_id					ca.ID%TYPE,
	max_interval			interval	DEFAULT	'1 day'
) RETURNS bigint[]
AS $$
DECLARE
	t_nowMinus1s				timestamp	:= date_trunc('second', now() AT TIME ZONE 'UTC') - interval '1 second';
	t_lastNotAfter_old			ca.LAST_NOT_AFTER%TYPE;
	t_lastNotAfter_new			ca.LAST_NOT_AFTER%TYPE;
	t_nextNotAfter_new			ca.NEXT_NOT_AFTER%TYPE;
	t_result					bigint[];
BEGIN
	SELECT ca.LAST_NOT_AFTER, least(t_nowMinus1s, ca.NEXT_NOT_AFTER + max_interval)
		INTO t_lastNotAfter_old, t_lastNotAfter_new
		FROM ca
		WHERE ca.ID = ca_id
		FOR UPDATE;

	SELECT ARRAY[coalesce(sum(CASE WHEN is_precertificate THEN 0 ELSE 1 END), 0), coalesce(sum(CASE WHEN is_precertificate THEN 1 ELSE 0 END), 0)]
		INTO t_result
		FROM certificate c
			INNER JOIN x509_hasExtension(c.CERTIFICATE, '1.3.6.1.4.1.11129.2.4.3', TRUE) is_precertificate ON TRUE
		WHERE c.ISSUER_CA_ID = ca_id
			AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > coalesce(t_lastNotAfter_old, '-infinity'::timestamp)
			AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) <= t_lastNotAfter_new;

	SELECT min(coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp))
		INTO t_nextNotAfter_new
		FROM certificate c
		WHERE c.ISSUER_CA_ID = ca_id
			AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > t_lastNotAfter_new;

	UPDATE ca
		SET NUM_EXPIRED[1] = coalesce(ca.NUM_EXPIRED[1], 0) + t_result[1],
			NUM_EXPIRED[2] = coalesce(ca.NUM_EXPIRED[2], 0) + t_result[2],
			LAST_NOT_AFTER = t_lastNotAfter_new,
			NEXT_NOT_AFTER = t_nextNotAfter_new
		WHERE ca.ID = ca_id;

	RETURN t_result;
END;
$$ LANGUAGE plpgsql;
