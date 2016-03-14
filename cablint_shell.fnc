/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2016 COMODO CA Limited
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

CREATE OR REPLACE FUNCTION cablint_shell(
	cert_data				bytea
) RETURNS text
LANGUAGE plsh
AS $$
#!/bin/sh
/bin/echo "$1" | /usr/bin/xxd -r -ps | /usr/bin/ruby -I /usr/local/certlint/lib /usr/local/bin/cablint /dev/stdin | PATH=/bin:/usr/bin sed "s/\tstdin$//g"
$$;
