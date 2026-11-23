"""Microsoft 365 check. Read-only: it asks Microsoft Graph only for read permissions and only
sends GET requests for data. Sign-in uses the device code flow; no token is saved to disk."""

import time

from . import exposure
from .findings import Finding, Result, now
from .http import ApiError, get, graph_pages, post_form
from .patterns import looks_like_ai_app

# Microsoft's public client for Graph command-line tools. Use --client-id to run with your
# own app registration instead (see docs/setup-m365.md).
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = ["User.Read.All", "Directory.Read.All", "Policy.Read.All", "Sites.Read.All",
          "SharePointTenantSettings.Read.All"]
GRAPH = "https://graph.microsoft.com/v1.0"
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}


# ---------------------------------------------------------------- sign-in

def sign_in(tenant="organizations", client_id=DEFAULT_CLIENT_ID, scopes=SCOPES):
    base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
    scope = " ".join(f"https://graph.microsoft.com/{s}" for s in scopes)
    dc = post_form(f"{base}/devicecode", {"client_id": client_id, "scope": scope})
    if "device_code" not in dc:
        raise SystemExit(f"Could not start sign-in: {dc.get('error_description') or dc.get('error')}")
    print(dc.get("message") or f"Open {dc['verification_uri']} and enter {dc['user_code']}")
    print("Sign in with a Global Reader or Global Administrator account.\n")
    interval = int(dc.get("interval", 5))
    deadline = time.time() + int(dc.get("expires_in", 900))
    while time.time() < deadline:
        time.sleep(interval)
        tok = post_form(f"{base}/token", {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                                         "client_id": client_id, "device_code": dc["device_code"]})
        if "access_token" in tok:
            return tok["access_token"]
        err = tok.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            interval += 5
            continue
        raise SystemExit(f"Sign-in failed: {tok.get('error_description') or err}")
    raise SystemExit("Sign-in timed out.")


# ---------------------------------------------------------------- analysis (pure, tested)

def analyse_sharepoint_settings(s):
    out = []
    cap = s.get("sharingCapability")
    if cap == "externalUserAndGuestSharing":
        out.append(Finding(
            id="m365-anyone-links-allowed", severity="medium",
            title="'Anyone' links are allowed in SharePoint and OneDrive",
            why="Any staff member can create a link that opens a file without signing in. These "
                "links are the main way case files and lists leak.",
            fix="In the SharePoint admin centre, Policies > Sharing: lower the setting to 'New and "
                "existing guests', or keep it but make 'Specific people' the default link and set "
                "an expiry for Anyone links.",
            items=[]))
    if s.get("isResharingByExternalUsersEnabled"):
        out.append(Finding(
            id="m365-external-reshare", severity="low", title="Guests can reshare files they were given",
            why="A partner can pass your file on to people you never invited.",
            fix="In the SharePoint admin centre, Policies > Sharing, turn off 'Allow guests to share "
                "items they don't own'.",
            items=[]))
    level = {"disabled": "no outside sharing", "existingExternalUserSharingOnly": "existing guests only",
             "externalUserSharingOnly": "new and existing guests",
             "externalUserAndGuestSharing": "anyone, including Anyone links"}.get(cap, cap or "unknown")
    return out, f"SharePoint and OneDrive outside sharing is set to: {level}."


def analyse_consent_policy(policy):
    assigned = ((policy or {}).get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or []
    if any("microsoft-user-default-legacy" in p for p in assigned):
        return Finding(
            id="m365-user-consent-any", severity="high", title="Staff can connect any app to their mail and files",
            why="AI note-takers and assistants ask staff for access to mail, calendars and files. "
                "With this setting anyone can say yes, and IT never sees it.",
            fix="In the Entra admin centre, Enterprise applications > Consent and permissions > User "
                "consent settings: choose verified publishers and low-risk permissions only, or no "
                "user consent, and turn on admin consent requests so staff can still ask.",
            items=[])
    if any("microsoft-user-default-low" in p for p in assigned):
        return Finding(
            id="m365-user-consent-low", severity="info",
            title="Staff can connect apps from verified publishers for low-risk permissions only",
            why="This is Microsoft's recommended middle setting.",
            fix="Nothing to change. Review the admin consent requests that come in.", items=[])
    self_grant = [p for p in assigned if p.startswith("ManagePermissionGrantsForSelf.")]
    if self_grant:
        return Finding(
            id="m365-user-consent-other", severity="info",
            title="Staff can connect some apps, under a Microsoft-managed or custom policy",
            why="Which apps staff can approve depends on the policy: " + ", ".join(
                p.split(".", 1)[1] for p in self_grant) + ".",
            fix="Check in the Entra admin centre (Enterprise applications > Consent and permissions) that "
                "this matches what you want, and turn on admin consent requests.", items=[])
    return Finding(id="m365-user-consent-none", severity="info", title="Staff cannot connect apps on their own",
                   why="Only admins can grant apps access to organisation data.",
                   fix="Make sure staff know how to ask, so they do not turn to personal accounts instead.",
                   items=[])


def analyse_mfa(security_defaults, ca_policies):
    """security_defaults: identitySecurityDefaultsEnforcementPolicy; ca_policies: list, or None
    when Conditional Access could not be read (no Entra ID P1)."""
    if (security_defaults or {}).get("isEnabled"):
        return Finding(id="m365-mfa-security-defaults", severity="info",
                       title="Security defaults are on: everyone must register for MFA",
                       why="This is the free baseline that blocks most password attacks.",
                       fix="Keep it on, unless you replace it with Conditional Access policies.", items=[])
    mfa_policies = [p for p in (ca_policies or []) if p.get("state") == "enabled" and
                    "mfa" in (((p.get("grantControls") or {}).get("builtInControls")) or [])]
    if mfa_policies:
        return Finding(id="m365-mfa-ca", severity="info",
                       title=f"Conditional Access requires MFA ({len(mfa_policies)} policies)",
                       why="Security defaults are off, but Conditional Access policies ask for MFA.",
                       fix="Check the policies cover all users, including admins, with no broad exclusions.",
                       items=[{"name": p.get("displayName", "")} for p in mfa_policies])
    return Finding(
        id="m365-mfa-off", severity="high", title="MFA does not appear to be enforced",
        why="Security defaults are off and no active Conditional Access policy asks for MFA. One phished "
            "password then opens that person's mail and files, and whatever an AI assistant can find for them.",
        fix="Turn security defaults on: Entra admin centre > Overview > Properties > Manage security "
            "defaults. If you use per-user MFA or another tool instead, check every account is covered.",
        items=[])


RISKY = {
    "mail": {"Mail.Read", "Mail.ReadWrite", "Mail.Send", "EWS.AccessAsUser.All", "IMAP.AccessAsUser.All",
             "full_access_as_user", "Mail.Read.Shared", "Mail.ReadWrite.Shared"},
    "files": {"Files.Read", "Files.Read.All", "Files.ReadWrite", "Files.ReadWrite.All", "Sites.Read.All",
              "Sites.ReadWrite.All", "Sites.FullControl.All", "Notes.Read.All"},
    "calendar": {"Calendars.Read", "Calendars.ReadWrite", "Calendars.Read.Shared"},
    "chats and meetings": {"Chat.Read", "Chat.ReadWrite", "ChannelMessage.Read.All", "OnlineMeetings.Read",
                           "OnlineMeetingTranscript.Read.All", "OnlineMeetingRecording.Read.All"},
}


def analyse_grants(grants, service_principals, own_app_id=None):
    """grants: oauth2PermissionGrants; service_principals: {id: servicePrincipal}.
    own_app_id: the app this check signed in with, so it does not report itself."""
    apps = {}
    for g in grants:
        sp = service_principals.get(g.get("clientId")) or {}
        if sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS:
            continue
        if own_app_id and sp.get("appId") == own_app_id:
            continue
        a = apps.setdefault(g.get("clientId"), {"name": sp.get("displayName") or g.get("clientId"),
                                                 "everyone": False, "people": 0, "scopes": set(),
                                                 "publisher": ((sp.get("verifiedPublisher") or {}).get("displayName")
                                                               or sp.get("publisherName") or "")})
        if g.get("consentType") == "AllPrincipals":
            a["everyone"] = True
        else:
            a["people"] += 1
        a["scopes"].update((g.get("scope") or "").split())
    ai, broad = [], []
    for a in apps.values():
        access = [label for label, s in RISKY.items() if a["scopes"] & s]
        item = {"name": a["name"], "granted for": "everyone" if a["everyone"] else
                f"{a['people']} {'person' if a['people'] == 1 else 'people'}",
                "access": ", ".join(access), "publisher": a["publisher"]}
        if looks_like_ai_app(a["name"]):
            ai.append(item)
        elif access:
            broad.append(item)
    out = []
    if ai:
        out.append(Finding(
            id="m365-apps-ai", severity="medium", title=f"AI and meeting-note apps with access to staff data ({len(ai)})",
            why="These apps can read what they were granted. Meeting bots join calls and keep "
                "transcripts; AI apps may store what they read outside your control.",
            fix="Decide which are allowed. Remove the rest in the Entra admin centre, Enterprise "
                "applications, and limit user consent (see the consent finding).",
            items=ai))
    if broad:
        out.append(Finding(
            id="m365-apps-broad", severity="low", title=f"Other apps with access to mail, files, calendars or chats ({len(broad)})",
            why="Old or unknown apps keep their access until someone removes it.",
            fix="Remove apps nobody uses, and review the list every few months.", items=broad))
    return out


def analyse_skus(skus):
    cop = [s for s in skus if "COPILOT" in (s.get("skuPartNumber") or "").upper()]
    if cop:
        used = sum(s.get("consumedUnits", 0) for s in cop)
        return Finding(
            id="m365-copilot-licences", severity="info", title=f"{used} Microsoft 365 Copilot licences assigned",
            why="Copilot answers from SharePoint, OneDrive, Teams and mail, using each person's own access. "
                "Oversharing found in this report becomes searchable for these people.",
            fix="Fix the 'Fix first' and 'Fix soon' items before assigning more licences.",
            items=[{"name": s.get("skuPartNumber"), "assigned": s.get("consumedUnits", 0)} for s in cop])
    return Finding(
        id="m365-copilot-none", severity="info", title="No Microsoft 365 Copilot licences",
        why="Staff may still have Microsoft 365 Copilot Chat, which works with the web and with what "
            "they paste or upload.",
        fix="Check its settings with docs/checklist.md, and fix oversharing before buying Copilot licences.",
        items=[])


def permission_exposure(perms, domains):
    """Widest exposure in a driveItem's permissions: anyone, domain, external or None."""
    domains = {d.lower() for d in domains}
    best = None
    rank = {"anyone": 3, "domain": 2, "external": 1}

    def bump(x):
        nonlocal best
        if best is None or rank[x] > rank[best]:
            best = x

    for p in perms:
        scope = (p.get("link") or {}).get("scope")
        if scope == "anonymous":
            bump("anyone")
        elif scope == "organization":
            bump("domain")
        grantees = [p.get("grantedToV2")] + list(p.get("grantedToIdentitiesV2") or [])
        for g in grantees:
            for ident in (g or {}).values():
                if not isinstance(ident, dict):
                    continue
                name = (ident.get("displayName") or "").lower()
                email = (ident.get("email") or ident.get("loginName") or "").lower()
                if name.startswith("everyone"):
                    bump("domain")
                elif "#ext#" in email or (domains and "@" in email and email.rsplit("@", 1)[1] not in domains):
                    bump("external")
    return best


def _where(site, item):
    path = ((item.get("parentReference") or {}).get("path") or "")
    path = path.split("root:", 1)[-1].strip("/")
    return f"{site}/{path}" if path else site


# ---------------------------------------------------------------- run

def run(tenant="organizations", client_id=DEFAULT_CLIENT_ID, max_sites=50, max_checks=3000):
    token = sign_in(tenant, client_id)
    r = Result(platform="Microsoft 365")
    domains = []

    def step(label, fn):
        print(f"  {label}...")
        try:
            fn()
        except ApiError as e:
            hint = " (the account may need Global Reader, or an admin must consent to the permission)" if e.status in (401, 403) else ""
            r.errors.append(f"{label}: {e.message}{hint}")

    def org():
        o = (get(f"{GRAPH}/organization", token, {"$select": "displayName,verifiedDomains"}).get("value") or [{}])[0]
        r.tenant = o.get("displayName", "")
        domains.extend(d.get("name", "") for d in o.get("verifiedDomains") or [])
        me = get(f"{GRAPH}/me", token, {"$select": "userPrincipalName"})
        r.coverage.append(f"Signed in as {me.get('userPrincipalName', 'unknown')}.")

    def sharing():
        fs, note = analyse_sharepoint_settings(get(f"{GRAPH}/admin/sharepoint/settings", token))
        for f in fs:
            r.add(f)
        r.coverage.append(note)

    def consent():
        r.add(analyse_consent_policy(get(f"{GRAPH}/policies/authorizationPolicy", token)))

    def apps():
        grants = list(graph_pages(f"{GRAPH}/oauth2PermissionGrants", token))
        sps = {}
        for cid in {g.get("clientId") for g in grants}:
            try:
                sps[cid] = get(f"{GRAPH}/servicePrincipals/{cid}", token, {
                    "$select": "id,appId,displayName,appOwnerOrganizationId,publisherName,verifiedPublisher"})
            except ApiError:
                sps[cid] = {}
        for f in analyse_grants(grants, sps, own_app_id=client_id):
            r.add(f)
        r.coverage.append("Apps: delegated permissions granted by staff or admins. Apps with "
                          "application permissions are not listed in this version.")

    def mfa():
        sd = get(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", token)
        ca = None
        if not sd.get("isEnabled"):
            try:
                ca = list(graph_pages(f"{GRAPH}/identity/conditionalAccess/policies", token))
            except ApiError:
                r.coverage.append("Conditional Access could not be read (it needs Entra ID P1, included "
                                  "in Business Premium); MFA was judged from security defaults only.")
        r.add(analyse_mfa(sd, ca))

    def licences():
        r.add(analyse_skus(list(graph_pages(f"{GRAPH}/subscribedSkus", token))))

    def guests():
        d = get(f"{GRAPH}/users", token, {"$filter": "userType eq 'Guest'", "$count": "true", "$top": 1,
                                          "$select": "id"}, headers={"ConsistencyLevel": "eventual"})
        n = d.get("@odata.count")
        if n:
            r.add(Finding(id="m365-guests", severity="info", title=f"{n} guest accounts",
                          why="Guests can open whatever has been shared with them, for as long as their account exists.",
                          fix="Review guests every few months in the Entra admin centre (Users, filter by Guest) "
                              "and remove those who no longer work with you.", items=[]))

    exposed = []

    def files():
        sites = list(graph_pages(f"{GRAPH}/sites", token, {"search": "*", "$select": "id,displayName,webUrl"},
                                 limit=max_sites))
        checks = scanned = 0
        for s in sites:
            sname = s.get("displayName") or s.get("webUrl", "")
            try:
                drives = list(graph_pages(f"{GRAPH}/sites/{s['id']}/drives", token, {"$select": "id,name"}))
            except ApiError:
                continue
            for d in drives:
                try:
                    items = [i for i in graph_pages(f"{GRAPH}/drives/{d['id']}/root/delta", token, {
                        "$select": "id,name,file,folder,parentReference,shared,deleted,root,webUrl"})
                             if not i.get("deleted") and not i.get("root")]
                except ApiError:
                    continue
                scanned += len(items)
                cands = [i for i in items if i.get("shared")] or [i for i in items if i.get("file")][:200]
                for i in cands:
                    if checks >= max_checks:
                        break
                    checks += 1
                    try:
                        perms = list(graph_pages(f"{GRAPH}/drives/{d['id']}/items/{i['id']}/permissions", token))
                    except ApiError:
                        continue
                    exp = permission_exposure(perms, domains)
                    if exp:
                        exposed.append({"name": i.get("name", ""), "exposure": exp,
                                        "how": {"anyone": "Anyone link", "domain": "whole organisation",
                                                "external": "people outside"}[exp],
                                        "kind": "folder" if i.get("folder") else "file",
                                        "where": _where(sname, i), "link": i.get("webUrl", "")})
        r.coverage.append(f"SharePoint: {len(sites)} sites the signed-in account can see "
                          f"(limit {max_sites}), {scanned} items, {checks} sharing checks"
                          f"{' (limit reached)' if checks >= max_checks else ''}. Personal OneDrives "
                          f"are not covered in this version.")

    step("Organisation", org)
    step("SharePoint sharing settings", sharing)
    step("App consent settings", consent)
    step("Connected apps", apps)
    step("MFA (security defaults)", mfa)
    step("Copilot licences", licences)
    step("Guest accounts", guests)
    step("Files shared widely", files)
    for f in exposure.findings(exposed, "m365"):
        r.add(f)
    r.add(Finding(id="m365-manual", severity="info", title="Copilot settings need a look by hand",
                  why="Some settings are not readable with read-only permissions, or need extra licences to report on.",
                  fix="Work through the Microsoft 365 part of docs/checklist.md: "
                      "Copilot Chat web search, agents, and 'Everyone except external users' on sites.",
                  items=[]))
    r.coverage.append("Only names and settings were read. No file contents were opened.")
    r.finished = now()
    return r
