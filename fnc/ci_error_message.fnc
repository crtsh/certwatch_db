CREATE OR REPLACE FUNCTION ci_error_message(
) RETURNS void
AS $$
DECLARE
BEGIN
	RAISE EXCEPTION 'Sorry, the "certificate_identity" table has been superseded by a Full Text Search index on the "certificate" table.';
END;
$$ LANGUAGE plpgsql STRICT IMMUTABLE;
