"""Microsoft 365 check. Read-only: it asks Microsoft Graph only for read permissions and only
sends GET requests for data. Sign-in opens the browser (authorization code with PKCE, redirect
to this computer); --no-browser uses a device code instead. No token is saved to disk."""

import re
import time
from datetime import datetime, timezone

from . import auth, exposure
from .findings import DOCS, Finding, Result, now
from .http import ApiError, get, graph_pages, post_form
from .patterns import looks_like_ai_app

# Microsoft's public client for Graph command-line tools. Use --client-id to run with your
# own app registration instead (see docs/setup-m365.md).
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
# Directory.Read.All also covers listing users (the guest count), so User.Read.All is not asked for.
SCOPES = ["Directory.Read.All", "Policy.Read.All", "Sites.Read.All", "SharePointTenantSettings.Read.All"]
GRAPH = "https://graph.microsoft.com/v1.0"
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}


# ---------------------------------------------------------------- sign-in

WHO = ("Approve and run with the same account: Global Administrator, or Global Reader plus a role that can "
       "approve app permissions, and a member of the SharePoint sites that hold case, HR and finance files. "
       "The check sees only what this account can open.")
CONSENT_TIP = ("If Microsoft asks you to approve permissions, you can leave 'Consent on behalf of your "
               "organization' unticked: the approval then covers only your account, not everyone who uses "
               "Microsoft Graph Command Line Tools in your organisation.")
BROWSER_HELP = ("If the browser shows a Microsoft error (for example AADSTS50011) and nothing happens here, "
                "press Ctrl+C, then run again with --no-browser, or with your own app registration "
                f"({DOCS}setup-m365.md).")
DEVICE_WARNING = ("Code sign-in: only enter this code for a sign-in you started yourself, here, just now. "
                  "Never enter a code that someone sent you: that is a known phishing trick. Some "
                  "organisations block this kind of sign-in; if yours does, run without --no-browser.")


def sign_in(tenant="organizations", client_id=DEFAULT_CLIENT_ID, scopes=SCOPES, no_browser=False):
    base = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0"
    scope = " ".join(f"https://graph.microsoft.com/{s}" for s in scopes)
    print(WHO)
    print(CONSENT_TIP + "\n")
    if no_browser:
        return _device_code(base, client_id, scope)
    try:
        code, redirect, verifier = auth.browser_code(
            f"{base}/authorize", client_id, scope, host="localhost", extra={"prompt": "select_account"},
            before_wait=BROWSER_HELP + "\n")
    except auth.SignInError as e:
        raise SystemExit(f"Sign-in did not complete: {e}.\n{BROWSER_HELP}") from None
    tok = post_form(f"{base}/token", {"client_id": client_id, "grant_type": "authorization_code", "code": code,
                                      "redirect_uri": redirect, "code_verifier": verifier, "scope": scope})
    if "access_token" not in tok:
        raise SystemExit(f"Sign-in failed: {tok.get('error_description') or tok.get('error')}\n{BROWSER_HELP}")
    return tok["access_token"]


def _device_code(base, client_id, scope):
    dc = post_form(f"{base}/devicecode", {"client_id": client_id, "scope": scope})
    if "device_code" not in dc:
        raise SystemExit(f"Could not start sign-in: {dc.get('error_description') or dc.get('error')}")
    print(DEVICE_WARNING + "\n")
    print(dc.get("message") or f"Open {dc['verification_uri']} and enter {dc['user_code']}")
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


# An emergency access ("break glass") account or two may be left out of a policy that otherwise
# covers everyone; more than that, or any excluded group or role, counts as a broad exclusion.
EMERGENCY_ACCOUNTS = 2
# Microsoft's own templates exclude the Directory Synchronization Accounts role (the service
# accounts Entra Connect uses) from MFA policies, so that exclusion does not make a policy partial.
# Role template id from Microsoft's list of Entra built-in roles.
DIRECTORY_SYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"


def covers_all(p, apps=("All",), strict=False):
    """Whether a Conditional Access policy applies to all users and to all apps (or one of the
    given app sets, such as Office365). With strict, excluded groups or roles, more than
    EMERGENCY_ACCOUNTS excluded users, or a sign-in or user risk condition (the policy then
    applies only to risky sign-ins) also make it partial."""
    return not _gaps(p, apps, strict)


def _gaps(p, apps=("All",), strict=False):
    cond = p.get("conditions") or {}
    users = cond.get("users") or {}
    gaps = []
    if "All" not in (users.get("includeUsers") or []):
        gaps.append("some people only")
    if not any(a in ((cond.get("applications") or {}).get("includeApplications") or []) for a in apps):
        gaps.append("some apps only")
    if strict:
        roles = [r for r in users.get("excludeRoles") or [] if r.lower() != DIRECTORY_SYNC_ROLE]
        if users.get("excludeGroups") or roles:
            gaps.append("excludes groups or roles")
        if len([u for u in users.get("excludeUsers") or [] if u != "GuestsOrExternalUsers"]) > EMERGENCY_ACCOUNTS:
            gaps.append("excludes more than two accounts")
        if cond.get("userRiskLevels") or cond.get("signInRiskLevels"):
            gaps.append("risky sign-ins only")
    return gaps


def _asks_for_mfa(p):
    g = p.get("grantControls") or {}
    return "mfa" in (g.get("builtInControls") or []) or bool(g.get("authenticationStrength"))


CA_MFA = "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength"


def analyse_mfa(security_defaults, ca_policies):
    """security_defaults: identitySecurityDefaultsEnforcementPolicy; ca_policies: list, or None
    when Conditional Access could not be read (no Entra ID P1). Only enabled policies count,
    and only one that covers everyone counts as enforcing MFA."""
    if (security_defaults or {}).get("isEnabled"):
        return Finding(id="m365-mfa-security-defaults", severity="info",
                       title="Security defaults are on: everyone must register for MFA",
                       why="This is the free baseline that blocks most password attacks.",
                       fix="Keep it on, unless you replace it with Conditional Access policies.", items=[])
    mfa_policies = [p for p in (ca_policies or []) if p.get("state") == "enabled" and _asks_for_mfa(p)]
    full = [p for p in mfa_policies if covers_all(p, apps=("All", "Office365"), strict=True)]
    if full:
        return Finding(id="m365-mfa-ca", severity="info",
                       title=f"Conditional Access requires MFA for everyone ({len(full)} {'policy' if len(full) == 1 else 'policies'})",
                       why="Security defaults are off, but at least one Conditional Access policy asks everyone "
                           "for MFA, for all apps or the Office 365 apps, with at most two accounts left out.",
                       fix="Check that the accounts left out are emergency access accounts, and that the policy "
                           "has no conditions (such as locations or device platforms) that skip MFA for most sign-ins.",
                       items=[{"name": p.get("displayName", "")} for p in full], sources=[CA_MFA])
    if mfa_policies:
        return Finding(
            id="m365-mfa-ca-partial", severity="medium",
            title="Conditional Access asks for MFA, but not from everyone",
            why="Security defaults are off, and no active Conditional Access policy asks all users for MFA. "
                "People the policies leave out can sign in with a password alone, so one phished password "
                "opens their mail and files, and whatever an AI assistant can find for them.",
            fix="Entra admin centre > Entra ID > Conditional Access > Policies: make sure one policy covers all "
                "users and all resources, excluding only your emergency access accounts, and asks for MFA. "
                "Start it in report-only and turn it on once the results look right.",
            items=[{"name": p.get("displayName", ""),
                    "note": ", ".join(_gaps(p, apps=("All", "Office365"), strict=True))}
                   for p in mfa_policies], sources=[CA_MFA])
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


# Microsoft 365 Copilot SKU part numbers, from Microsoft's licensing service plan reference
# (learn.microsoft.com/entra/identity/users/licensing-service-plan-reference). Other SKUs with
# "Copilot" in the name (Copilot Studio, Copilot for Sales and so on) are listed but not counted.
COPILOT_SKUS = {"MICROSOFT_365_COPILOT", "M365_COPILOT", "MICROSOFT_365_COPILOT_EDU"}
SAM_COPILOT = "https://learn.microsoft.com/en-us/sharepoint/sharepoint-advanced-management-features-copilot-license"
DAG = "https://learn.microsoft.com/en-us/sharepoint/data-access-governance-reports"
COPILOT_CHAT = "https://learn.microsoft.com/en-us/copilot/overview"


def analyse_skus(skus):
    named = [s for s in skus if "COPILOT" in (s.get("skuPartNumber") or "").upper()]
    confirmed = [s for s in named if (s.get("skuPartNumber") or "").upper() in COPILOT_SKUS]
    other = [s for s in named if s not in confirmed]
    used = sum(s.get("consumedUnits", 0) or 0 for s in confirmed)
    items = ([{"name": s.get("skuPartNumber"), "assigned": s.get("consumedUnits", 0)} for s in confirmed] +
             [{"name": s.get("skuPartNumber"), "assigned": s.get("consumedUnits", 0),
               "note": "not counted: not a Microsoft 365 Copilot licence this check recognises"} for s in other])
    unsure = (" Other Copilot-named licences were found but not counted; if one of them is a Microsoft 365 "
              "Copilot licence (for example Copilot Business), treat this as 'licences assigned'.") if other else ""
    if used >= 1:
        return Finding(
            id="m365-copilot-licences", severity="info", title=f"{used} Microsoft 365 Copilot licences assigned",
            why="Copilot answers from SharePoint, OneDrive, Teams and mail, using each person's own access. "
                "Oversharing found in this report becomes searchable for these people." + unsure,
            fix="Fix the 'Fix first' and 'Fix soon' items before assigning more licences. Microsoft says that "
                "one assigned Copilot licence also brings SharePoint Advanced Management features, including "
                "oversharing reports that cover every site, which this check does not. See whether SharePoint "
                "admin centre > Reports > Data access governance is there, and run the site permissions report.",
            items=items, sources=[SAM_COPILOT, DAG])
    return Finding(
        id="m365-copilot-none", severity="info", title="No assigned Microsoft 365 Copilot licences found",
        why="Without a Copilot licence, Copilot Chat cannot search your files through Microsoft Graph. It "
            "uses what people paste or upload, what they have open in Outlook or Teams, and pay-as-you-go "
            "agents if you allow them. Connected AI apps and Anyone links in this report matter either way." + unsure,
        fix=f"Check the Copilot Chat and agent settings with {DOCS}checklist.md, and fix oversharing before "
            "buying Copilot licences.",
        items=items, sources=[COPILOT_CHAT])


BLOCK_FLOWS = "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows"


def analyse_device_code(ca_policies):
    """ca_policies: Conditional Access policies, or None when they could not be read (then this
    says nothing). Report-only policies do not count as blocking."""
    if ca_policies is None:
        return None
    blocking = []
    for p in ca_policies:
        cond = p.get("conditions") or {}
        flows = ((cond.get("authenticationFlows") or {}).get("transferMethods") or "")
        if (p.get("state") == "enabled" and "deviceCodeFlow" in [x.strip() for x in flows.split(",")]
                and "block" in (((p.get("grantControls") or {}).get("builtInControls")) or [])):
            blocking.append(p)
    everyone = [p for p in blocking if covers_all(p)]
    if everyone:
        return Finding(id="m365-device-code-blocked", severity="info",
                       title="Device code sign-in is blocked by Conditional Access",
                       why="This sign-in method is a common phishing route. Microsoft recommends blocking it.",
                       fix="Nothing to change. This check then needs the browser sign-in (its default).",
                       items=[{"name": p.get("displayName", "")} for p in everyone], sources=[BLOCK_FLOWS])
    return Finding(
        id="m365-device-code-open", severity="low", title="Device code sign-in is not blocked for everyone",
        why="Attackers send people a code with a real Microsoft address and ask them to 'sign in'. Whoever "
            "enters the code hands the attacker a session with their mail and files. Microsoft recommends "
            "blocking this sign-in method wherever possible.",
        fix="Entra admin centre > Entra ID > Conditional Access > Policies. If a Microsoft-managed policy that "
            "blocks device code flow is listed in report-only mode, review it and turn it on. Otherwise create "
            "one: all users (exclude your emergency access account), all resources, Conditions > Authentication "
            "flows > Device code flow, Grant > Block access. Start in report-only and turn it on once the "
            "results look right.",
        items=[{"name": p.get("displayName", ""), "note": "blocks some people or apps only"} for p in blocking],
        sources=[BLOCK_FLOWS])


# SharePoint's sign-in names for its organisation-wide claims, the same in every language:
# "Everyone except external users" (c:0-.f|rolemanager|spo-grid-all-users/<tenant id>) and
# "Everyone" (c:0(.s|true). Display names are translated ("Tout le monde sauf les utilisateurs
# externes"), so the English prefix alone misses localised tenants.
ORG_WIDE_LOGINS = ("spo-grid-all-users", "c:0(.s|true")
NO_EXPIRY_BEFORE = 2  # Microsoft uses DateTime.MinValue (year 1) for "no expiry"


def _parse_time(text):
    """A Graph timestamp to an aware datetime, or None. Copes with 'Z' and with seven-digit
    fractions, which Python 3.10's fromisoformat does not."""
    if not text:
        return None
    t = re.sub(r"(\.\d+)", "", str(text).strip()).replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def expired(perm, when=None):
    """True when a permission has an expiry date that has passed. No date, Microsoft's
    'no expiry' value (year 1) or a date that cannot be read all count as not expired."""
    d = _parse_time(perm.get("expirationDateTime"))
    if d is None or d.year < NO_EXPIRY_BEFORE:
        return False
    return d <= (when or datetime.now(timezone.utc))


PUBLIC_GROUPS = "https://support.microsoft.com/topic/c0a991b3-9c56-48b8-bf0f-05530f836b1b"
PUBLIC_SITE_MEMBERS = ("https://learn.microsoft.com/en-us/troubleshoot/sharepoint/sharing-and-permissions/"
                       "everyone-except-external-user-removed")


def analyse_public_groups(groups):
    """groups: Microsoft 365 (Unified) groups with visibility and resourceProvisioningOptions.
    Returns a list of findings. Public groups are reported (anyone in the organisation can join
    them and see their content); Viva Engage's own organisation-wide groups get a separate note."""
    public = [g for g in groups if (g.get("visibility") or "").lower() == "public"
              and "Unified" in (g.get("groupTypes") or ["Unified"])]
    built_in = [g for g in public if is_viva_engage_default(g)]
    public = [g for g in public if not is_viva_engage_default(g)]

    def item(g):
        return {"name": g.get("displayName") or g.get("id", ""),
                "kind": "team" if "Team" in (g.get("resourceProvisioningOptions") or []) else "group",
                "mail": g.get("mail") or ""}

    out = []
    if built_in:
        out.append(Finding(
            id="m365-public-groups-builtin", severity="info",
            title=f"Organisation-wide groups created by Viva Engage ({len(built_in)})",
            why="Viva Engage creates an 'All Company' group (and a system group for its Answers feature) that "
                "is open to everyone by design.",
            fix="Leave them as they are, but make sure nobody keeps case, HR or finance files in them.",
            items=[item(g) for g in sorted(built_in, key=lambda g: (g.get("displayName") or "").lower())]))
    if not public:
        return out
    items = [item(g) for g in sorted(public, key=lambda g: (g.get("displayName") or "").lower())]
    out.append(Finding(
        id="m365-public-groups", severity="medium",
        title=f"Public Microsoft 365 groups and teams ({len(public)})",
        why="Anyone in the organisation can join a public group or team without an owner's approval and see "
            "what is inside it. By default its SharePoint site also gives 'Everyone except external users' "
            "member access, so its files turn up in search and in Copilot answers for every colleague. "
            "This check does not look inside these sites unless the "
            "signed-in account is a member.",
        fix="Ask each owner whether the group or team holds case, HR, finance or other private files. If it "
            "does, make it private (a group owner or admin can change its privacy setting; Microsoft 365 admin "
            "centre > Teams & groups > Active teams & groups shows owners). Groups meant for the whole "
            "organisation, such as an all-staff team, can stay public if nothing private is kept there.",
        items=items, sources=[PUBLIC_GROUPS, PUBLIC_SITE_MEMBERS]))
    return out


def is_viva_engage_default(g):
    """The 'All Company' group Viva Engage creates, and its 'Group for Answers in Viva Engage'
    system group. Both are organisation-wide on purpose."""
    name = (g.get("displayName") or "").strip().lower()
    return name == "all company" or name.startswith("group for answers in viva engage")


def permission_exposure(perms, domains, when=None):
    """Widest exposure in a driveItem's permissions: anyone, domain, external or None.
    Permissions that have expired (before 'when', default now) are skipped."""
    domains = {d.lower() for d in domains}
    best = None
    rank = {"anyone": 3, "domain": 2, "external": 1}

    def bump(x):
        nonlocal best
        if best is None or rank[x] > rank[best]:
            best = x

    for p in perms:
        if expired(p, when):
            continue
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
                login = (ident.get("loginName") or "").lower()
                email = (ident.get("email") or login).lower()
                if name.startswith("everyone") or any(c in login for c in ORG_WIDE_LOGINS):
                    bump("domain")
                elif "#ext#" in email or (domains and "@" in email and email.rsplit("@", 1)[1] not in domains):
                    bump("external")
    return best


def _where(site, item):
    path = ((item.get("parentReference") or {}).get("path") or "")
    path = path.split("root:", 1)[-1].strip("/")
    return f"{site}/{path}" if path else site


# ---------------------------------------------------------------- run

SAMPLE = 200  # files checked per library when Microsoft returns no 'shared' flags


SHOW_SKIPPED = 10


def sharepoint_coverage(sites, max_sites, scanned, checks, max_checks, sampled, skipped=()):
    """What the file check saw, stated plainly, so a short report is not read as an all-clear.
    skipped: sites not checked, or not finished, because the sharing-check limit was reached."""
    skipped = list(skipped)
    names = ", ".join(skipped[:SHOW_SKIPPED]) + (f" and {len(skipped) - SHOW_SKIPPED} more"
                                                 if len(skipped) > SHOW_SKIPPED else "")
    return (f"SharePoint: {sites} sites this account can see (limit {max_sites}), {scanned} items, {checks} "
            f"sharing checks (limit {max_checks}{', reached' if checks >= max_checks else ''}). "
            + (f"Because the limit was reached, {len(skipped)} "
               f"{'site was' if len(skipped) == 1 else 'sites were'} not checked or not finished: {names}. "
               if skipped else "")
            + (f"In {sampled} libraries Microsoft marked no item as shared, so only the first {SAMPLE} files "
               "there were checked. " if sampled else "")
            + "Admin roles do not open site content: sites this account is not a member or owner of were "
              "not checked, so run it with an account that belongs to the sites that hold case, HR and finance "
              "files. Microsoft returns all sharing details only to an item's owners; elsewhere only the sharing "
              "that applies to this account is shown, so Anyone links made by others can be missed. Personal "
              "OneDrives are not covered in this version. Microsoft's Data access governance reports (with "
              "SharePoint Advanced Management) cover every site.")


AFTERWARDS = ("When you are done, remove the approval you gave. If you ticked 'Consent on behalf of your "
              "organization': Entra admin centre > Enterprise apps > Microsoft Graph Command Line Tools > "
              "Permissions > Admin consent, then for each permission this check added choose ... > Revoke "
              "permission (keep any your IT team uses with Microsoft Graph PowerShell). If you left it "
              "unticked, the approval covers only your account; the portal cannot remove that kind, so see "
              f"{DOCS}setup-m365.md#afterwards. With your own app registration, delete the registration.")


def run(tenant="organizations", client_id=DEFAULT_CLIENT_ID, max_sites=50, max_checks=3000, no_browser=False,
        keywords=None):
    token = sign_in(tenant, client_id, no_browser=no_browser)
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
        if ca is None:
            r.coverage.append("Device code sign-in was not checked: blocking it needs Conditional Access, which "
                              + ("is not used while security defaults are on." if sd.get("isEnabled")
                                 else "could not be read."))
        r.add(analyse_device_code(ca))

    def licences():
        r.add(analyse_skus(list(graph_pages(f"{GRAPH}/subscribedSkus", token))))

    def groups():
        gs = list(graph_pages(f"{GRAPH}/groups", token, {
            "$filter": "groupTypes/any(c:c eq 'Unified')", "$top": 999,
            "$select": "id,displayName,mail,visibility,groupTypes,resourceProvisioningOptions"}))
        for f in analyse_public_groups(gs):
            r.add(f)
        r.coverage.append(f"Microsoft 365 groups and teams: {len(gs)} listed, "
                          f"{sum(1 for g in gs if (g.get('visibility') or '').lower() == 'public')} public.")

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
        checks = scanned = sampled = 0
        skipped = []  # sites not checked, or not finished, because the sharing-check limit was reached
        for s in sites:
            sname = s.get("displayName") or s.get("webUrl", "")
            if checks >= max_checks:
                skipped.append(sname)
                continue
            try:
                drives = list(graph_pages(f"{GRAPH}/sites/{s['id']}/drives", token, {"$select": "id,name"}))
            except ApiError:
                continue
            stopped = False
            for d in drives:
                if checks >= max_checks:
                    stopped = True
                    break
                try:
                    items = [i for i in graph_pages(f"{GRAPH}/drives/{d['id']}/root/delta", token, {
                        "$select": "id,name,file,folder,parentReference,shared,deleted,root,webUrl,lastModifiedDateTime"})
                             if not i.get("deleted") and not i.get("root")]
                except ApiError:
                    continue
                scanned += len(items)
                cands = [i for i in items if i.get("shared")]
                if not cands:
                    cands = [i for i in items if i.get("file")][:SAMPLE]
                    sampled += 1 if cands else 0
                for i in cands:
                    if checks >= max_checks:
                        stopped = True
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
                                        "where": _where(sname, i), "link": i.get("webUrl", ""),
                                        "modified": (i.get("lastModifiedDateTime") or "")[:10]})
            if stopped:
                skipped.append(sname)
        r.coverage.append(sharepoint_coverage(len(sites), max_sites, scanned, checks, max_checks, sampled, skipped))

    step("Organisation", org)
    step("SharePoint sharing settings", sharing)
    step("App consent settings", consent)
    step("Connected apps", apps)
    step("MFA and device code sign-in", mfa)
    step("Copilot licences", licences)
    step("Public groups and teams", groups)
    step("Guest accounts", guests)
    step("Files shared widely", files)
    for f in exposure.findings(exposed, "m365", keywords):
        r.add(f)
    r.summary = exposure.summary(exposed, keywords)
    r.add(Finding(id="m365-manual", severity="info", title="Copilot settings need a look by hand",
                  why="Some settings are not readable with read-only permissions, or need extra licences to report on.",
                  fix=f"Work through the Microsoft 365 part of {DOCS}checklist.md: Copilot Chat web search, "
                      "agents, and 'Everyone except external users' added by hand to sites that are not public groups.",
                  items=[]))
    r.coverage.append("Only names and settings were read. No file contents were opened.")
    r.finished = now()
    return r
