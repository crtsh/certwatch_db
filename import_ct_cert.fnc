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

CREATE OR REPLACE FUNCTION import_ct_cert(
	ct_log_id				ct_log.ID%TYPE,
	ct_log_entry_id			ct_log_entry.ENTRY_ID%TYPE,
	ct_log_timestamp		bigint,
	cert_data				bytea
) RETURNS certificate.ID%TYPE
AS $$
DECLARE
	t_certificateID		certificate.ID%TYPE;
BEGIN
	t_certificateID := import_cert(cert_data);
	IF t_certificateID IS NULL THEN
		RETURN NULL;
	END IF;

	INSERT INTO ct_log_entry (
			CERTIFICATE_ID, CT_LOG_ID, ENTRY_ID,
			ENTRY_TIMESTAMP
		)
		SELECT t_certificateID, ct_log_id, ct_log_entry_id,
			timestamp without time zone 'epoch'
				+ (ct_log_timestamp * interval '1 millisecond');

	RETURN t_certificateID;
END;
$$ LANGUAGE plpgsql;
