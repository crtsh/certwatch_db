\timing on

SELECT max(gin_clean_pending_list(psui.INDEXRELID)) FROM pg_stat_user_indexes psui WHERE psui.RELNAME LIKE 'certificate%' AND psui.INDEXRELNAME LIKE '%identities%';
