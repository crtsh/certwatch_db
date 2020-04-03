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

CREATE OR REPLACE FUNCTION lint_summarizer(
) RETURNS TRIGGER
AS $$
DECLARE
	t_noOfCerts				lint_summary.NO_OF_CERTS%TYPE;
BEGIN
	IF TG_OP = 'INSERT' THEN
		INSERT INTO lint_summary (
				LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE, NO_OF_CERTS
			)
			VALUES (
				new.LINT_ISSUE_ID, new.ISSUER_CA_ID, new.NOT_BEFORE_DATE, 1
			)
			ON CONFLICT (LINT_ISSUE_ID, ISSUER_CA_ID, NOT_BEFORE_DATE) DO UPDATE
				SET NO_OF_CERTS = lint_summary.NO_OF_CERTS + 1;
		RETURN NEW;
	ELSIF TG_OP = 'DELETE' THEN
		UPDATE lint_summary
			SET NO_OF_CERTS = NO_OF_CERTS - 1
			WHERE LINT_ISSUE_ID = old.LINT_ISSUE_ID
				AND ISSUER_CA_ID = old.ISSUER_CA_ID
				AND NOT_BEFORE_DATE = old.NOT_BEFORE_DATE
			RETURNING NO_OF_CERTS
				INTO t_noOfCerts;
		IF FOUND AND (t_noOfCerts = 0) THEN
			DELETE FROM lint_summary
				WHERE LINT_ISSUE_ID = old.LINT_ISSUE_ID
					AND ISSUER_CA_ID = old.ISSUER_CA_ID
					AND NOT_BEFORE_DATE = old.NOT_BEFORE_DATE
					AND NO_OF_CERTS = 0;
		END IF;
		RETURN OLD;
	END IF;
END;
$$ LANGUAGE plpgsql STRICT;
