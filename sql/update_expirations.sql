\timing on

\set ON_ERROR_STOP on

DO
$$DECLARE
	l_ca		RECORD;
	t_counts	bigint[];
	t_expiredUpTo	text;
BEGIN
	FOR l_ca IN (
		SELECT ca.ID, ca.NEXT_NOT_AFTER
			FROM ca
			WHERE ca.NEXT_NOT_AFTER < date_trunc('second', now() AT TIME ZONE 'UTC')
			ORDER BY ca.NEXT_NOT_AFTER
	) LOOP
		SELECT *
			INTO t_counts
			FROM update_expirations(l_ca.ID, '10 minutes'::interval);
		COMMIT;

		IF (l_ca.NEXT_NOT_AFTER + interval '10 minutes') > (now() AT TIME ZONE 'UTC') THEN
			t_expiredUpTo := 'NOW';
		ELSE
			t_expiredUpTo := to_char(l_ca.NEXT_NOT_AFTER + interval '10 minutes', 'YYYY-MM-DD HH24:MI:SS');
		END IF;
		RAISE NOTICE 'CA ID: %    # Certs Expired: %    # Precerts Expired: %    (expired up to %)', l_ca.ID, coalesce(t_counts[1], 0), coalesce(t_counts[2], 0), t_expiredUpTo;
	END LOOP;
END$$;
