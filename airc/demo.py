"""A made-up organisation, run through the real analysis code, so anyone can see what a report
looks like without signing in. Every name here is fictional."""

from . import exposure, google_ws, m365
from .findings import Result, now

ORG = "demo-ngo.example"


def google_result():
    r = Result(platform="Google Workspace", tenant=ORG + " (demo data)")
    users = [
        {"primaryEmail": f"director@{ORG}", "isAdmin": True, "isEnrolledIn2Sv": True},
        {"primaryEmail": f"it-volunteer@{ORG}", "isAdmin": True, "isEnrolledIn2Sv": False},
        {"primaryEmail": f"caseworker1@{ORG}", "isEnrolledIn2Sv": False},
        {"primaryEmail": f"caseworker2@{ORG}", "isEnrolledIn2Sv": True},
        {"primaryEmail": f"finance@{ORG}", "isEnrolledIn2Sv": True},
        {"primaryEmail": f"former-intern@{ORG}", "isEnrolledIn2Sv": False, "suspended": True},
    ]
    for f in google_ws.analyse_users(users):
        r.add(f)
    r.active_accounts = len(google_ws.active_users(users))
    files = google_ws.files_from_drive({
        "anyoneWithLink": [
            {"id": "1", "name": "Beneficiary list Q3 2026.xlsx", "modifiedTime": "2026-10-28T08:00:00Z",
             "owners": [{"emailAddress": f"caseworker1@{ORG}"}]},
            {"id": "2", "name": "Workshop photos", "mimeType": google_ws.FOLDER, "modifiedTime": "2024-05-14T10:00:00Z",
             "owners": [{"emailAddress": f"director@{ORG}"}]},
            {"id": "5", "name": "Export final v3.xlsx", "modifiedTime": "2026-09-30T16:20:00Z",
             "owners": [{"emailAddress": f"caseworker2@{ORG}"}]},
            {"id": "6", "name": "Annual report 2024.pdf", "modifiedTime": "2025-03-02T12:00:00Z",
             "owners": [{"emailAddress": f"director@{ORG}"}]},
        ],
        "domainWithLink": [
            {"id": "3", "name": "Salaires 2026.xlsx", "modifiedTime": "2026-11-01T09:00:00Z",
             "owners": [{"emailAddress": f"finance@{ORG}"}]},
            {"id": "4", "name": "Team meeting notes", "modifiedTime": "2026-11-18T15:00:00Z",
             "owners": [{"emailAddress": f"director@{ORG}"}]},
        ],
    })
    audit = [{"id": {"time": "2026-10-02T09:12:00Z"}, "events": [{"name": "change_document_visibility", "parameters": [
        {"name": "doc_id", "value": "9"}, {"name": "doc_title", "value": "GBV case notes - field office"},
        {"name": "visibility", "value": "people_with_link"}, {"name": "owner", "value": f"caseworker2@{ORG}"},
        {"name": "doc_type", "value": "folder"}]}]}]
    files += google_ws.files_from_audit(audit, {f["id"] for f in files})
    for f in exposure.findings(files, "gws"):
        r.add(f)
    r.summary = exposure.summary(files)
    tokens = [{"actor": {"email": f"caseworker1@{ORG}"}, "id": {"time": "2026-11-03T10:00:00Z"}, "events": [{
        "name": "authorize", "parameters": [{"name": "app_name", "value": "Fireflies.ai Meeting Notes"},
                                            {"name": "client_id", "value": "abc"},
                                            {"name": "scope", "multiValue": ["https://www.googleapis.com/auth/calendar.readonly",
                                                                             "https://www.googleapis.com/auth/drive"]}]}]},
              {"actor": {"email": f"director@{ORG}"}, "id": {"time": "2026-11-12T14:00:00Z"}, "events": [{
                  "name": "authorize", "parameters": [{"name": "app_name", "value": "Granola"},
                                                      {"name": "client_id", "value": "def"},
                                                      {"name": "scope", "multiValue": [
                                                          "https://www.googleapis.com/auth/calendar.events.readonly"]}]}]}]
    for f in google_ws.analyse_tokens(tokens):
        r.add(f)
    for f in google_ws.analyse_shared_drives([{"name": "Protection team", "restrictions": {"domainUsersOnly": False}},
                                              {"name": "Finance", "restrictions": {"domainUsersOnly": True}}]):
        r.add(f)
    r.add(google_ws.GEMINI_MANUAL)
    r.checked = ["accounts", "files", "apps"]
    r.coverage.append("Demo data: a made-up organisation, run through the same analysis code as a real check.")
    r.finished = now()
    return r


def m365_result():
    r = Result(platform="Microsoft 365", tenant="Demo NGO (demo data)")
    fs, note = m365.analyse_sharepoint_settings({"sharingCapability": "externalUserAndGuestSharing"})
    for f in fs:
        r.add(f)
    r.coverage.append(note)
    r.add(m365.analyse_consent_policy({"defaultUserRolePermissions": {
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}))
    sps = {"sp1": {"displayName": "Otter.ai", "appOwnerOrganizationId": "x"},
           "sp2": {"displayName": "Old Survey Tool", "appOwnerOrganizationId": "y"},
           "sp3": {"displayName": "Zapier", "appOwnerOrganizationId": "z"}}
    grants = [{"clientId": "sp1", "consentType": "Principal", "scope": "openid Calendars.Read OnlineMeetings.Read"},
              {"clientId": "sp2", "consentType": "AllPrincipals", "scope": "Files.Read.All"},
              {"clientId": "sp3", "consentType": "Principal", "scope": "openid Mail.Read Mail.Send Files.ReadWrite.All"}]
    for f in m365.analyse_grants(grants, sps):
        r.add(f)
    r.add(m365.analyse_skus([{"skuPartNumber": "Microsoft_365_Copilot", "consumedUnits": 3}]))
    ca = [{"displayName": "Require MFA for everyone", "state": "enabled",
           "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
           "grantControls": {"builtInControls": ["mfa"]}}]
    r.add(m365.analyse_mfa({"isEnabled": False}, ca))
    r.add(m365.analyse_device_code(ca))
    for f in m365.analyse_public_groups([
        {"displayName": "Protection team", "visibility": "Public", "groupTypes": ["Unified"],
         "resourceProvisioningOptions": ["Team"]},
        {"displayName": "All staff", "visibility": "Public", "groupTypes": ["Unified"]},
        {"displayName": "Finance", "visibility": "Private", "groupTypes": ["Unified"]}]):
        r.add(f)
    domains = ["demongo.example"]
    perms_by_file = [
        ("Passport scans - arrivals", "folder", "Protection/Intake", "2026-08-11", [{"link": {"scope": "anonymous"}}]),
        ("Export final v3.xlsx", "file", "Programmes/Data", "2026-11-04", [{"link": {"scope": "anonymous"}}]),
        ("Donor list 2026.xlsx", "file", "Fundraising", "2026-10-20",
         [{"grantedToV2": {"siteGroup": {"displayName": "Everyone except external users"}}}]),
        ("Partner MoU draft.docx", "file", "Programmes", "2025-06-02",
         [{"grantedToV2": {"user": {"email": "someone@partner.example"}}}]),
    ]
    files = []
    for name, kind, where, modified, perms in perms_by_file:
        exp = m365.permission_exposure(perms, domains)
        files.append({"name": name, "kind": kind, "where": "Demo NGO/" + where, "exposure": exp, "modified": modified,
                      "how": {"anyone": "Anyone link", "domain": "whole organisation", "external": "people outside"}[exp]})
    for f in exposure.findings(files, "m365"):
        r.add(f)
    r.summary = exposure.summary(files)
    r.coverage.append(m365.sharepoint_coverage(6, 50, 412, 37, 3000, 1))
    r.active_accounts = 18
    r.coverage.append("Accounts: 18 enabled member accounts and 0 guests.")
    r.checked = ["apps", "mfa", "groups", "accounts", "files"]
    r.coverage.append("Demo data: a made-up organisation, run through the same analysis code as a real check.")
    r.finished = now()
    return r


def run():
    return [google_result(), m365_result()]
