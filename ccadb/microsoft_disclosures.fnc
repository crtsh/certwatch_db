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

CREATE OR REPLACE FUNCTION microsoft_disclosures(
) RETURNS text
AS $$
DECLARE
	t_undisclosed					text[];
	t_undisclosedSummary			text;
	t_incomplete					text[];
	t_incompleteSummary				text;
	t_inconsistentAudit				text[];
	t_inconsistentAuditSummary		text;
	t_inconsistentCPS				text[];
	t_inconsistentCPSSummary		text;
	t_trustRevoked					text[];
	t_notTrusted					text[];
	t_expired						text[];
	t_constrained					text[];
	t_constrainedOther				text[];
	t_revokedButExpired				text[];
	t_revokedViaDisallowedSTL		text[];
	t_revoked						text[];
	t_parentRevoked					text[];
	t_disclosedButExpired			text[];
	t_disclosedButNotTrusted		text[];
	t_disclosedButInDisallowedSTL	text[];
	t_disclosedButConstrained		text[];
	t_disclosedWithErrors			text[];
	t_disclosedButInCRL				text[];
	t_disclosedAndUnrevokedFromCRL	text[];
	t_disclosed						text[];
	t_unknown						text[];
BEGIN
	t_undisclosed := ccadb_disclosure_group2(1, 'Undisclosed', 'undisclosed', 'Unconstrained Trust: Disclosure is required!', '#FE838A');
	t_undisclosedSummary := ccadb_disclosure_group_summary(1, 'Undisclosed', 'undisclosedsummary', '#FE838A');
	t_incomplete := ccadb_disclosure_group2(1, 'DisclosureIncomplete', 'disclosureincomplete', 'Certificate disclosed, but CP/CPS or Audit details missing or incorrect: Further Disclosure is required!', '#FE838A');
	t_incompleteSummary := ccadb_disclosure_group_summary(1, 'DisclosureIncomplete', 'disclosureincompletesummary', '#FE838A');
	t_inconsistentAudit := ccadb_disclosure_group2(1, 'DisclosedWithInconsistentAudit', 'disclosedwithinconsistentaudit', '[EXPERIMENTAL] Certificate disclosed, but Audit details for the Subject CA are inconsistent: Further Disclosure is required!', '#F8B88B');
	t_inconsistentAuditSummary := ccadb_disclosure_group_summary(1, 'DisclosedWithInconsistentAudit', 'disclosedwithinconsistentauditsummary', '#F8B88B');
	t_inconsistentCPS := ccadb_disclosure_group2(1, 'DisclosedWithInconsistentCPS', 'disclosedwithinconsistentcps', '[EXPERIMENTAL] Certificate disclosed, but CP/CPS details for the Subject CA are inconsistent: Further Disclosure is required!', '#F8B88B');
	t_inconsistentCPSSummary := ccadb_disclosure_group_summary(1, 'DisclosedWithInconsistentCPS', 'disclosedwithinconsistentcpssummary', '#F8B88B');
	t_trustRevoked := ccadb_disclosure_group(1, 'AllSuitablePathsRevoked', 'trustrevoked', 'Unconstrained, although all unexpired paths contain at least one revoked intermediate: Disclosure is not known to be required', '#FAF884');
	t_notTrusted := ccadb_disclosure_group(1, 'NoKnownSuitableTrustPath', 'nottrusted', 'Unconstrained, but no suitable unexpired trust paths have been observed: Disclosure is not known to be required', '#FAF884');
	t_expired := ccadb_disclosure_group(1, 'Expired', 'expired', 'Expired: Disclosure is not required', '#BAED91');
	t_constrained := ccadb_disclosure_group(1, 'TechnicallyConstrained', 'constrained', 'Technically Constrained (Trusted): Disclosure is not currently required', '#BAED91');
	t_constrainedOther := ccadb_disclosure_group(1, 'TechnicallyConstrainedOther', 'constrainedother', 'Technically Constrained (Other): Disclosure is not required', '#BAED91');
	t_revokedButExpired := ccadb_disclosure_group(1, 'RevokedButExpired', 'revokedbutexpired', 'Disclosed as Revoked or Parent Revoked, but Expired', '#B2CEFE');
	t_revokedViaDisallowedSTL := ccadb_disclosure_group(1, 'RevokedViaOneCRL', 'revokedviaonecrl', 'Disclosed as Revoked and in disallowedcert.stl', '#B2CEFE');
	t_revoked := ccadb_disclosure_group(1, 'Revoked', 'revoked', 'Disclosed as Revoked, but not currently in disallowedcert.stl', '#B2CEFE');
	t_parentRevoked := ccadb_disclosure_group(1, 'ParentRevoked', 'parentrevoked', 'Disclosed as Parent Revoked, so not currently in disallowedcert.stl', '#B2CEFE');
	t_disclosedButExpired := ccadb_disclosure_group(1, 'DisclosedButExpired', 'disclosedbutexpired', 'Disclosed, but Expired', '#F2A2E8');
	t_disclosedButNotTrusted := ccadb_disclosure_group(1, 'DisclosedButNoKnownSuitableTrustPath', 'disclosedbutnottrusted', 'Disclosed, but no suitable unexpired trust paths have been observed', '#F2A2E8');
	t_disclosedButInDisallowedSTL := ccadb_disclosure_group(1, 'DisclosedButInOneCRL', 'disclosedbutinonecrl', 'Disclosed (as Not Revoked), but Revoked via disallowedcert.stl', '#F2A2E8');
	t_disclosedButConstrained := ccadb_disclosure_group(1, 'DisclosedButConstrained', 'disclosedbutconstrained', 'Disclosed, but Technically Constrained', '#F2A2E8');
	t_disclosedWithErrors := ccadb_disclosure_group(1, 'DisclosedWithErrors', 'disclosedwitherrors', 'Disclosed, but with Errors: Parent Certificate Name is set incorrectly', '#F2A2E8');
	t_disclosedButInCRL := ccadb_disclosure_group(1, 'DisclosedButInCRL', 'disclosedbutincrl', 'Disclosed (as Not Revoked), but revoked via CRL', '#F2A2E8');
	t_disclosedAndUnrevokedFromCRL := ccadb_disclosure_group(1, 'DisclosedButRemovedFromCRL', 'disclosedandunrevokedfromcrl', 'Disclosed (as Not Revoked) and "Unrevoked" from CRL', '#F2A2E8');
	t_disclosed := ccadb_disclosure_group(1, 'Disclosed', 'disclosed', 'Disclosed', '#F2A2E8');
	t_unknown := ccadb_disclosure_group(1, NULL::disclosure_status_type, 'unknown', 'Disclosed; Unknown to crt.sh or Incorrectly Encoded', '#FFFFFF');

	RETURN
'  <SPAN class="whiteongrey">Microsoft: CA Certificate Disclosures in CCADB</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH>Category</TH>
    <TH>Disclosure Required?</TH>
    <TH># of CA certs</TH>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Unconstrained Trust</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#undisclosed">' || t_undisclosed[2] || ' + ' || t_undisclosed[3] || '</A>
      &nbsp;<A href="#undisclosedsummary" style="font-size:8pt">Summary</A></TD>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Disclosure Incomplete or Incorrect</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosureincomplete">' || t_incomplete[2] || ' + ' || t_incomplete[3] || '</A>
      &nbsp;<A href="#disclosureincompletesummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#F8B88B">
    <TD>[EXPERIMENTAL] Disclosed, but with Inconsistent Audit details</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosedwithinconsistentaudit">' || t_inconsistentAudit[2] || ' + ' || t_inconsistentAudit[3] || '</A>
      &nbsp;<A href="#disclosedwithinconsistentauditsummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#F8B88B">
    <TD>[EXPERIMENTAL] Disclosed, but with Inconsistent CP/CPS details</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosedwithinconsistentcps">' || t_inconsistentCPS[2] || ' + ' || t_inconsistentCPS[3] || '</A>
      &nbsp;<A href="#disclosedwithinconsistentcpssummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#FAF884">
    <TD>Unconstrained, but all unexpired observed paths Revoked</TD>
    <TD>Unknown</TD>
    <TD><A href="#trustrevoked">' || t_trustRevoked[2] || '</A></TD>
  </TR>
  <TR style="background-color:#FAF884">
    <TD>Unconstrained, but zero unexpired observed paths</TD>
    <TD>Unknown</TD>
    <TD><A href="#nottrusted">' || t_notTrusted[2] || '</A></TD>
  </TR>
  <TR style="background-color:#BAED91">
    <TD>Expired</TD>
    <TD>No</TD>
    <TD><A href="#expired">' || t_expired[2] || '</A></TD>
  </TR>
  <TR style="background-color:#BAED91">
    <TD>Technically Constrained (Trusted)</TD>
    <TD><A href="//www.mail-archive.com/dev-security-policy@lists.mozilla.org/msg06905.html" target="_blank">Maybe soon?</A></TD>
    <TD><A href="#constrained">' || t_constrained[2] || '</A></TD>
  </TR>
  <TR style="background-color:#BAED91">
    <TD>Technically Constrained (Other)</TD>
    <TD>No</TD>
    <TD><A href="#constrainedother">' || t_constrainedOther[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked, but Expired</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revokedbutexpired">' || t_revokedButExpired[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked and in <A href="/revoked-intermediates" target="_blank">disallowedcert.stl</A></TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revokedviaonecrl">' || t_revokedViaDisallowedSTL[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked (but not in <A href="/revoked-intermediates" target="_blank">disallowedcert.stl</A>)</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revoked">' || t_revoked[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Parent Revoked (so not in <A href="/revoked-intermediates" target="_blank">disallowedcert.stl</A>)</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#parentrevoked">' || t_parentRevoked[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but Expired</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutexpired">' || t_disclosedButExpired[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but zero unexpired observed paths</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutnottrusted">' || t_disclosedButNotTrusted[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed (as Not Revoked), but in <A href="/revoked-intermediates" target="_blank">disallowedcert.stl</A></TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutinonecrl">' || t_disclosedButInDisallowedSTL[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but Technically Constrained</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutconstrained">' || t_disclosedButConstrained[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but with Errors</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedwitherrors">' || t_disclosedWithErrors[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed (as Not Revoked), but Revoked via CRL</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutincrl">' || t_disclosedButInCRL[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed (as Not Revoked) and "Unrevoked" from CRL</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedandunrevokedfromcrl">' || t_disclosedAndUnrevokedFromCRL[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosed">' || t_disclosed[2] || '</A></TD>
  </TR>
  <TR>
    <TD>Unknown to crt.sh or Incorrectly Encoded</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#unknown">' || t_unknown[2] || '</TD>
  </TR>
</TABLE>
'
		|| t_undisclosed[1]
		|| t_undisclosedSummary
		|| t_incomplete[1]
		|| t_incompleteSummary
		|| t_inconsistentAudit[1]
		|| t_inconsistentAuditSummary
		|| t_inconsistentCPS[1]
		|| t_inconsistentCPSSummary
		|| t_trustRevoked[1]
		|| t_notTrusted[1]
		|| t_expired[1]
		|| t_constrained[1]
		|| t_constrainedOther[1]
		|| t_revokedButExpired[1]
		|| t_revokedViaDisallowedSTL[1]
		|| t_revoked[1]
		|| t_parentRevoked[1]
		|| t_disclosedButExpired[1]
		|| t_disclosedButNotTrusted[1]
		|| t_disclosedButInDisallowedSTL[1]
		|| t_disclosedButConstrained[1]
		|| t_disclosedWithErrors[1]
		|| t_disclosedButInCRL[1]
		|| t_disclosedAndUnrevokedFromCRL[1]
		|| t_disclosed[1]
		|| t_unknown[1];
END;
$$ LANGUAGE plpgsql;
