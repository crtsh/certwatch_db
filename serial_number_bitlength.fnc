CREATE OR REPLACE FUNCTION serial_number_bitlength(
	serial_number			bytea
) RETURNS integer
AS $$
DECLARE
	t_hex					text;
	t_byte1					integer;
	t_bitLength				integer		:= 0;
BEGIN
	t_hex := ltrim(encode(serial_number, 'hex'), '0');
	t_byte1 := get_byte(decode(lpad(substr(t_hex, 1, 1), 2, '0'), 'hex'), 0);
	t_bitLength := (length(t_hex) * 4) - 4;
	WHILE t_byte1 > 0 LOOP
		t_byte1 := t_byte1 >> 1;
		t_bitLength := t_bitLength + 1;
	END LOOP;
	IF t_bitLength < 0 THEN
		t_bitLength := 0;
	END IF;
	RETURN t_bitLength;
END;
$$ LANGUAGE plpgsql STRICT;
