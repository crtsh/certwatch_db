CREATE OR REPLACE FUNCTION chrome_disclosures(
) RETURNS text
AS $$
DECLARE
	t_undisclosed					text[];
	t_undisclosedSummary			text;
	t_constrained					text[];
	t_constrainedSummary			text;
	t_incomplete					text[];
	t_incompleteSummary				text;
	t_inconsistentAudit				text[];
	t_inconsistentAuditSummary		text;
	t_inconsistentCPS				text[];
	t_inconsistentCPSSummary		text;
	t_trustRevoked					text[];
	t_notTrusted					text[];
	t_expired						text[];
	t_constrainedOther				text[];
	t_parentRevokedButNotAllParents	text[];
	t_parentRevoked					text[];
	t_revokedButExpired				text[];
	t_revokedAndConstrained			text[];
	t_revoked						text[];
	t_disclosedButExpired			text[];
	t_disclosedButNotTrusted		text[];
	t_disclosedAndConstrained		text[];
	t_disclosedWithErrors			text[];
	t_disclosedButInCRL				text[];
	t_disclosedAndUnrevokedFromCRL	text[];
	t_disclosed						text[];
	t_unknown						text[];
BEGIN
	t_undisclosed := ccadb_disclosure_group2(6, 'Undisclosed', 'undisclosed', 'Unconstrained (Trusted for serverAuth): Disclosure is required!', '#FE838A');
	t_undisclosedSummary := ccadb_disclosure_group_summary(6, 'Undisclosed', 'undisclosedsummary', '#FE838A');
	t_constrained := ccadb_disclosure_group2(6, 'TechnicallyConstrained', 'constrained', 'Technically Constrained (Trusted for serverAuth): Disclosure is required!', '#FE838A');
	t_constrainedSummary := ccadb_disclosure_group_summary(6, 'TechnicallyConstrained', 'constrainedsummary', '#FE838A');
	t_incomplete := ccadb_disclosure_group2(6, 'DisclosureIncomplete', 'disclosureincomplete', 'Certificate disclosed, but CP/CPS or Audit details missing or incorrect: Further Disclosure is required!', '#FE838A');
	t_incompleteSummary := ccadb_disclosure_group_summary(6, 'DisclosureIncomplete', 'disclosureincompletesummary', '#FE838A');
	t_inconsistentAudit := ccadb_disclosure_group2(6, 'DisclosedWithInconsistentAudit', 'disclosedwithinconsistentaudit', 'Certificate disclosed, but Audit details for the Subject CA are inconsistent: Further Disclosure is required!', '#F8B88B');
	t_inconsistentAuditSummary := ccadb_disclosure_group_summary(6, 'DisclosedWithInconsistentAudit', 'disclosedwithinconsistentauditsummary', '#F8B88B');
	t_inconsistentCPS := ccadb_disclosure_group2(6, 'DisclosedWithInconsistentCPS', 'disclosedwithinconsistentcps', 'Certificate disclosed, but CP/CPS details for the Subject CA are inconsistent: Further Disclosure is required!', '#F8B88B');
	t_inconsistentCPSSummary := ccadb_disclosure_group_summary(6, 'DisclosedWithInconsistentCPS', 'disclosedwithinconsistentcpssummary', '#F8B88B');
	t_trustRevoked := ccadb_disclosure_group(6, 'AllServerAuthPathsRevoked', 'trustrevoked', 'Unconstrained, although all unexpired paths contain at least one revoked intermediate: Disclosure is not known to be required', '#FAF884');
	t_notTrusted := ccadb_disclosure_group(6, 'NoKnownServerAuthTrustPath', 'nottrusted', 'Unconstrained, but no unexpired trust paths have been observed: Disclosure is not known to be required', '#FAF884');
	t_expired := ccadb_disclosure_group(6, 'Expired', 'expired', 'Expired: Disclosure is not required', '#BAED91');
	t_constrainedOther := ccadb_disclosure_group(6, 'TechnicallyConstrainedOther', 'constrainedother', 'Technically Constrained (Other): Disclosure is required!', '#BAED91');
	t_parentRevokedButNotAllParents := ccadb_disclosure_group(6, 'ParentRevokedButNotAllParents', 'parentrevokedbutnotallparents', 'Disclosed as Parent Revoked, but not all parent(s) are disclosed as Revoked', '#B2CEFE');
	t_parentRevoked := ccadb_disclosure_group(6, 'ParentRevoked', 'parentrevoked', 'Disclosed as Parent Revoked', '#B2CEFE');
	t_revokedButExpired := ccadb_disclosure_group(6, 'RevokedButExpired', 'revokedbutexpired', 'Disclosed as Revoked, but Expired', '#B2CEFE');
	t_revokedAndConstrained := ccadb_disclosure_group(6, 'RevokedAndTechnicallyConstrained', 'revokedandconstrained', 'Disclosed as Revoked and Technically Constrained', '#B2CEFE');
	t_revoked := ccadb_disclosure_group(6, 'Revoked', 'revoked', 'Disclosed as Revoked', '#B2CEFE');
	t_disclosedButExpired := ccadb_disclosure_group(6, 'DisclosedButExpired', 'disclosedbutexpired', 'Disclosed, but Expired', '#F2A2E8');
	t_disclosedButNotTrusted := ccadb_disclosure_group(6, 'DisclosedButNoKnownServerAuthTrustPath', 'disclosedbutnottrusted', 'Disclosed, but no unexpired trust paths have been observed', '#F2A2E8');
	t_disclosedAndConstrained := ccadb_disclosure_group(6, 'DisclosedButConstrained', 'disclosedbutconstrained', 'Disclosed, and Technically Constrained', '#F2A2E8');
	t_disclosedWithErrors := ccadb_disclosure_group(6, 'DisclosedWithErrors', 'disclosedwitherrors', 'Disclosed, but with Errors: Parent Certificate Name is set incorrectly', '#F2A2E8');
	t_disclosedButInCRL := ccadb_disclosure_group(6, 'DisclosedButInCRL', 'disclosedbutincrl', 'Disclosed (as Not Revoked), but revoked via CRL', '#F2A2E8');
	t_disclosedAndUnrevokedFromCRL := ccadb_disclosure_group(6, 'DisclosedButRemovedFromCRL', 'disclosedandunrevokedfromcrl', 'Disclosed (as Not Revoked) and "Unrevoked" from CRL', '#F2A2E8');
	t_disclosed := ccadb_disclosure_group(6, 'Disclosed', 'disclosed', 'Disclosed', '#F2A2E8');
	t_unknown := ccadb_disclosure_group(6, NULL::disclosure_status_type, 'unknown', 'Disclosed; Unknown to crt.sh or Incorrectly Encoded', '#FFFFFF');

	RETURN
'  <SPAN class="whiteongrey">Chrome: CA Certificate Disclosures in CCADB</SPAN>
  <BR><SPAN class="small">Generated at ' || TO_CHAR(statement_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC</SPAN>
<BR><BR>
<TABLE>
  <TR>
    <TH>Category</TH>
    <TH>(Further) Disclosure Required?</TH>
    <TH># of CA certs</TH>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Unconstrained (Trusted for serverAuth)</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#undisclosed">' || t_undisclosed[2] || ' + ' || t_undisclosed[3] || '</A>
      &nbsp;<A href="#undisclosedsummary" style="font-size:8pt">Summary</A></TD>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Technically Constrained (Trusted for serverAuth)</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#constrained">' || t_constrained[2] || ' + ' || t_constrained[3] || '</A>
      &nbsp;<A href="#constrainedsummary" style="font-size:8pt">Summary</A></TD>
  </TR>
  <TR style="background-color:#FE838A">
    <TD>Disclosure Incomplete or Incorrect</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosureincomplete">' || t_incomplete[2] || ' + ' || t_incomplete[3] || '</A>
      &nbsp;<A href="#disclosureincompletesummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#F8B88B">
    <TD>Disclosed, but with Inconsistent Audit details</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosedwithinconsistentaudit">' || t_inconsistentAudit[2] || ' + ' || t_inconsistentAudit[3] || '</A>
      &nbsp;<A href="#disclosedwithinconsistentauditsummary" style="font-size:8pt">Summary</A>
    </TD>
  </TR>
  <TR style="background-color:#F8B88B">
    <TD>Disclosed, but with Inconsistent CP/CPS details</TD>
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
    <TD>Technically Constrained (Other)</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#constrainedother">' || t_constrainedOther[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Parent Revoked, but not all parent(s) are disclosed as Revoked</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#parentrevokedbutnotallparents">' || t_parentRevokedButNotAllParents[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Parent Revoked</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#parentrevoked">' || t_parentRevoked[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked, but Expired</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revokedbutexpired">' || t_revokedButExpired[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked and Technically Constrained</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revokedandconstrained">' || t_revokedAndConstrained[2] || '</A></TD>
  </TR>
  <TR style="background-color:#B2CEFE">
    <TD>Disclosed as Revoked</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#revoked">' || t_revoked[2] || '</A></TD>
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
    <TD>Disclosed, and Technically Constrained</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedbutconstrained">' || t_disclosedAndConstrained[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed, but with Errors</TD>
    <TD>Already disclosed</TD>
    <TD><A href="#disclosedwitherrors">' || t_disclosedWithErrors[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed (as Not Revoked), but Revoked via CRL</TD>
    <TD><B><U>Yes!</U></B></TD>
    <TD><A href="#disclosedbutincrl">' || t_disclosedButInCRL[2] || '</A></TD>
  </TR>
  <TR style="background-color:#F2A2E8">
    <TD>Disclosed (as Not Revoked) and "Unrevoked" from CRL</TD>
    <TD><B><U>Yes!</U></B></TD>
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
		|| t_constrained[1]
		|| t_constrainedSummary
		|| t_incomplete[1]
		|| t_incompleteSummary
		|| t_inconsistentAudit[1]
		|| t_inconsistentAuditSummary
		|| t_inconsistentCPS[1]
		|| t_inconsistentCPSSummary
		|| t_trustRevoked[1]
		|| t_notTrusted[1]
		|| t_expired[1]
		|| t_constrainedOther[1]
		|| t_parentRevokedButNotAllParents[1]
		|| t_parentRevoked[1]
		|| t_revokedButExpired[1]
		|| t_revokedAndConstrained[1]
		|| t_revoked[1]
		|| t_disclosedButExpired[1]
		|| t_disclosedButNotTrusted[1]
		|| t_disclosedAndConstrained[1]
		|| t_disclosedWithErrors[1]
		|| t_disclosedButInCRL[1]
		|| t_disclosedAndUnrevokedFromCRL[1]
		|| t_disclosed[1]
		|| t_unknown[1];
END;
$$ LANGUAGE plpgsql;
