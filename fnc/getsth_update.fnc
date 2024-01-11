/* certwatch_db - Database schema
 * Written by Rob Stradling
 * Copyright (C) 2015-2024 Sectigo Limited
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

CREATE OR REPLACE FUNCTION getsth_update(
) RETURNS void
AS $$
DECLARE
BEGIN
	UPDATE ct_log ctl
		SET TREE_SIZE = CASE WHEN gut.LATEST_STH_TIMESTAMP > coalesce(ctl.LATEST_STH_TIMESTAMP, '-infinity'::date) THEN gut.TREE_SIZE ELSE ctl.TREE_SIZE END,
			LATEST_STH_TIMESTAMP = CASE WHEN gut.LATEST_STH_TIMESTAMP > coalesce(ctl.LATEST_STH_TIMESTAMP, '-infinity'::date) THEN gut.LATEST_STH_TIMESTAMP ELSE ctl.LATEST_STH_TIMESTAMP END,
			LATEST_UPDATE = gut.LATEST_UPDATE
		FROM getsth_update_temp gut
		WHERE ID = gut.CT_LOG_ID;
END;
$$ LANGUAGE plpgsql;
