/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
