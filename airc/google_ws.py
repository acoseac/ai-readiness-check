"""Google Workspace check. Read-only: it asks Google only for read-only scopes and only sends
GET requests for data. Sign-in uses your own OAuth client (see docs/setup-google.md) and a
browser redirect to this computer (or a pasted address with --no-browser); no token is saved
to disk."""

import json
from datetime import datetime, timedelta, timezone

from . import auth, exposure
from .findings import DOCS, Finding, Result, now
from .http import ApiError, check_url, get, google_pages, post_form
from .access import C, R, RC, RSC, S, SC, can_act, describe
from .patterns import looks_like_ai_app

SCOPES = [
    "openid",
    "email",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
]

DIRECTORY = "https://admin.googleapis.com/admin/directory/v1"
REPORTS = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications"
DRIVE = "https://www.googleapis.com/drive/v3"
FOLDER = "application/vnd.google-apps.folder"


# ---------------------------------------------------------------- sign-in

def load_client(client_file):
    with open(client_file, encoding="utf-8") as fh:
        cfg = json.load(fh)
    c = cfg.get("installed") or cfg.get("web")
    if not c or "client_id" not in c:
        raise SystemExit("That file does not look like a Google OAuth client (Desktop app). "
                         "See docs/setup-google.md.")
    c.setdefault("auth_uri", "https://accounts.google.com/o/oauth2/auth")
    c.setdefault("token_uri", "https://oauth2.googleapis.com/token")
    for key in ("auth_uri", "token_uri"):
        try:
            check_url(c[key])
        except ApiError:
            raise SystemExit(f"client.json sends sign-in to {c[key]!r}, which is not a Google address this "
                             "tool uses. Download the client file again from Google Cloud.") from None
    return c


def sign_in(client_file, scopes=SCOPES, no_browser=False, timeout=300):
    c = load_client(client_file)
    print("Sign in with a Google Workspace super admin account.")
    if not no_browser:
        print("A browser window opens. If it opens in the wrong browser or profile, copy the address "
              "below into the browser where your admin account is signed in.")
    try:
        code, redirect, verifier = auth.browser_code(
            c["auth_uri"], c["client_id"], " ".join(scopes), host="127.0.0.1", paste=no_browser,
            extra={"access_type": "online", "prompt": "consent"}, timeout=timeout)
    except auth.SignInError as e:
        raise SystemExit(f"Sign-in did not complete: {e}.") from None
    tok = post_form(c["token_uri"], {
        "code": code, "client_id": c["client_id"], "client_secret": c.get("client_secret", ""),
        "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier,
    })
    if "access_token" not in tok:
        raise SystemExit(f"Sign-in failed: {tok.get('error_description') or tok.get('error')}")
    return tok["access_token"]


# ---------------------------------------------------------------- analysis (pure, tested)

def active_users(users):
    return [u for u in users if not u.get("suspended") and not u.get("archived")]


def analyse_users(users):
    active = active_users(users)
    admins = [u for u in active if u.get("isAdmin") or u.get("isDelegatedAdmin")]
    out = [Finding(
        id="gws-accounts", severity="info",
        title=f"{len(active)} active accounts, {len(admins)} with admin rights",
        why="Each account is a way in to everything it can open, and an AI assistant makes that "
            "content quicker to search.",
        fix="Suspend accounts of people who have left, and keep admin rights to two or three people.")]
    no2sv_admins = [u for u in admins if not u.get("isEnrolledIn2Sv")]
    if no2sv_admins:
        out.append(Finding(
            id="gws-admin-2sv", severity="high",
            title=f"Admins without 2-step verification ({len(no2sv_admins)})",
            why="An admin account can open or reset almost anything. If its password is phished, "
                "the attacker gets the organisation's data, and its AI assistant, with it.",
            fix="Enrol these admins in 2-step verification today, preferably with a passkey or "
                "security key, then enforce it for all admins (Security > Authentication > "
                "2-step verification).",
            items=[{"name": u.get("primaryEmail", "")} for u in no2sv_admins]))
    no2sv = [u for u in active if not u.get("isEnrolledIn2Sv") and u not in no2sv_admins]
    if no2sv:
        out.append(Finding(
            id="gws-user-2sv", severity="medium",
            title=f"Staff accounts without 2-step verification ({len(no2sv)})",
            why="A phished password gives access to that person's mail and files, and to whatever "
                "an AI assistant can find for them.",
            fix="Enrol everyone in 2-step verification and then enforce it.",
            items=[{"name": u.get("primaryEmail", "")} for u in no2sv]))
    return out


VIS = {"anyoneCanFind": ("anyone", "public on the web"),
       "anyoneWithLink": ("anyone", "anyone with the link"),
       "domainCanFind": ("domain", "findable by everyone in the organisation"),
       "domainWithLink": ("domain", "everyone in the organisation with the link")}


def files_from_drive(files_by_visibility):
    """{visibility: [Drive file]} from files.list to exposure dicts."""
    out = []
    for vis, files in files_by_visibility.items():
        exp, how = VIS[vis]
        for f in files:
            owners = f.get("owners") or []
            out.append({"id": f.get("id"), "name": f.get("name", ""), "exposure": exp, "how": how,
                        "kind": "folder" if f.get("mimeType") == FOLDER else "file",
                        "owner": owners[0].get("emailAddress") if owners else "shared drive",
                        "seen": "admin view", "modified": (f.get("modifiedTime") or "")[:10],
                        "link": f.get("webViewLink") or (f"https://drive.google.com/open?id={f['id']}" if f.get("id") else "")})
    return out


AUDIT_VIS = {"people_with_link": ("anyone", "anyone with the link"),
             "public_on_the_web": ("anyone", "public on the web"),
             "people_within_domain_with_link": ("domain", "everyone in the organisation with the link"),
             "public_in_the_domain": ("domain", "findable by everyone in the organisation"),
             "shared_externally": ("external", "shared with people outside")}


def _params(event):
    p = {}
    for x in event.get("parameters", []) or []:
        p[x.get("name")] = x.get("value", x.get("multiValue", x.get("boolValue")))
    return p


def files_from_audit(activities, known_ids=()):
    """Latest visibility per document from Drive audit 'change_document_visibility' events,
    newest first as the Reports API returns them."""
    latest = {}
    for act in activities:
        when = (act.get("id") or {}).get("time", "")[:10]
        for ev in act.get("events", []) or []:
            if ev.get("name") != "change_document_visibility":
                continue
            p = _params(ev)
            doc = p.get("doc_id")
            if not doc or doc in latest:
                continue
            latest[doc] = (p, when)
    out = []
    for doc, (p, when) in latest.items():
        if doc in known_ids or p.get("visibility") not in AUDIT_VIS:
            continue
        exp, how = AUDIT_VIS[p["visibility"]]
        out.append({"id": doc, "name": p.get("doc_title", "(no title)"), "exposure": exp, "how": how,
                    "kind": "folder" if p.get("doc_type") == "folder" else "file",
                    "owner": p.get("owner", ""), "seen": f"audit log, sharing set {when}",
                    "link": f"https://drive.google.com/open?id={doc}"})
    return out


# What each scope lets an app do, from Google's OAuth 2.0 scopes list
# (developers.google.com/identity/protocols/oauth2/scopes). https://mail.google.com/: "Read,
# compose, send, and permanently delete all your email"; gmail.modify: "Read, compose, and send";
# gmail.compose: "Manage drafts and send"; gmail.insert: "Add emails into your Gmail mailbox";
# drive: "See, edit, create, and delete all of your Google Drive files"; calendar: "See, edit,
# share, and permanently delete all the calendars you can access"; calendar.events: "View and
# edit events on all your calendars". drive.file (only files used with the app) and the Gmail
# settings scopes are not counted.
G = "https://www.googleapis.com/auth/"
ACCESS = {
    "mail": {"https://mail.google.com/": RSC, G + "gmail.modify": RSC, G + "gmail.readonly": R,
             G + "gmail.metadata": R, G + "gmail.send": S, G + "gmail.compose": SC, G + "gmail.insert": C},
    "all files": {G + "drive": RC, G + "drive.readonly": R},
    "calendar": {G + "calendar": RC, G + "calendar.readonly": R, G + "calendar.events": RC,
                 G + "calendar.events.readonly": R, G + "calendar.events.owned": RC,
                 G + "calendar.events.owned.readonly": R},
}
FIRST_PARTY = ("google ", "android", "chrome", "gmail", "my google")
GOOGLE_AI = ("gemini", "notebooklm", "ai test kitchen", "google ai studio", "bard")
DEVICES = {"macos", "ios", "ios account manager", "android", "windows"}


TOKEN_EVENTS = ("authorize", "revoke")


def latest_grants(activities, own_client_ids=()):
    """From token audit 'authorize' and 'revoke' events, the grants still in place: the latest
    event per person and app decides, so an app that was authorised and later revoked is left
    out. Returns (who, params, time) for each grant still authorised."""
    latest = {}
    for act in activities:
        who = (act.get("actor") or {}).get("email", "")
        when = (act.get("id") or {}).get("time", "")
        for ev in act.get("events", []) or []:
            if ev.get("name") not in TOKEN_EVENTS:
                continue
            p = _params(ev)
            if p.get("client_id") in own_client_ids:
                continue
            key = (who, p.get("client_id") or (p.get("app_name") or "").strip().lower())
            if key not in latest or when > latest[key][2]:
                latest[key] = (ev.get("name"), p, when)
    return [(who, p, when) for (who, _), (name, p, when) in latest.items() if name == "authorize"]


def analyse_tokens(activities, own_client_ids=()):
    """activities: token audit events, 'authorize' and 'revoke'. own_client_ids: this tool's own
    OAuth client, so it does not report itself."""
    apps = {}
    for who, p, when in latest_grants(activities, own_client_ids):
        name = p.get("app_name") or p.get("client_id") or "(unnamed app)"
        a = apps.setdefault(name.strip().lower(), {"name": name, "users": set(), "scopes": set(), "last": ""})
        a["users"].add(who)
        sc = p.get("scope") or []
        a["scopes"].update(sc if isinstance(sc, list) else [sc])
        a["last"] = max(a["last"], when[:10])
    ai, google_ai, broad = [], [], []
    for a in apps.values():
        low = a["name"].lower()
        if low in DEVICES:
            continue  # the built-in mail and calendar apps on phones and laptops
        access, _ = describe(a["scopes"], ACCESS)
        item = {"name": a["name"], "people": len(a["users"]), "access": access, "last": a["last"]}
        if low.startswith(GOOGLE_AI):
            google_ai.append(item)
        elif low.startswith(FIRST_PARTY):
            continue
        elif looks_like_ai_app(a["name"]):
            ai.append(item)
        elif access:
            broad.append(item)

    def order(items):
        return sorted(items, key=lambda i: (not can_act(i["access"]), -i["people"]))

    out = []
    if ai:
        acting = sum(1 for i in ai if can_act(i["access"]))
        out.append(Finding(
            id="gws-apps-ai", severity="medium",
            title=f"Outside AI, meeting-note and automation apps connected to accounts ({len(ai)}"
                  + (f", {acting} can send or change" if acting else "") + ")",
            why="These apps were given access to staff accounts. Meeting bots join calls and keep "
                "transcripts; AI apps may store or learn from what they read, outside your control. Apps that "
                "can send or change matter most: an AI app that reads an email or document with hidden "
                "instructions in it (prompt injection) could be led to send mail or change files as the person "
                "who connected it. Automation platforms such as Zapier, Make and n8n are listed too, because "
                "they often run AI steps.",
            fix="For each one, starting with those that can send or change, decide whether it is allowed. "
                "Remove the ones that are not (Security > "
                "Access and data control > API controls > App access control), and limit which "
                "apps staff can connect. An app already set to Blocked there may still be listed here, "
                "because blocking it does not add a revoke to the token log.",
            items=order(ai)))
    if google_ai:
        out.append(Finding(
            id="gws-apps-google-ai", severity="info", title=f"Google AI apps in use ({len(google_ai)})",
            why="Google's own AI apps follow your Workspace settings, but people may use them more widely "
                "than you think, and with access to mail and Drive.",
            fix="Check that the Gemini settings in the Admin console match how you want them used "
                f"(see {DOCS}checklist.md).",
            items=sorted(google_ai, key=lambda i: -i["people"])))
    if broad:
        out.append(Finding(
            id="gws-apps-broad", severity="low", title=f"Other apps with access to mail, all files or calendars ({len(broad)})",
            why="Any connected app can read what it was granted. Old or unknown ones are a quiet way out for data, "
                "and those that can send or change can also act as the people who connected them.",
            fix="Remove apps nobody uses, and review the list every few months.",
            items=order(broad)))
    return out


def analyse_shared_drives(drives):
    open_out = [d for d in drives if not (d.get("restrictions") or {}).get("domainUsersOnly")]
    if not open_out:
        return []
    return [Finding(
        id="gws-shared-drives-external", severity="low",
        title=f"Shared drives that allow sharing outside the organisation ({len(open_out)} of {len(drives)})",
        why="Files in these drives can be shared with outside people by any manager of the drive.",
        fix="For drives that hold case, HR or finance files, open the drive's settings and turn "
            "off access for people outside the organisation.",
        items=[{"name": d.get("name", "")} for d in open_out])]


GEMINI_GMAIL_POST = ("https://workspaceupdates.googleblog.com/2026/11/"
                     "expanding-gemini-in-gmail-to-more-Google-Workspace-users.html")
GEMINI_FEATURE_ACCESS = ("https://knowledge.workspace.google.com/admin/generative-ai/workspace-with-gemini/"
                         "manage-access-to-gemini-features-in-workspace-services")

GEMINI_MANUAL = Finding(
    id="gws-gemini-manual", severity="info", title="Gemini settings need a look by hand",
    why="This check does not read Gemini settings. On Business and Enterprise editions, the Gemini app's "
        "connection to Workspace apps such as Drive and Gmail is on by default. Since 10 November 2026, "
        "Gmail's AI Overview thread summaries and Help me write (non-personalised) are rolling out to all "
        "Workspace editions, on by default for people aged 18 and over who have smart features on.",
    fix="In the Admin console, open Generative AI and check who can use the Gemini app and NotebookLM, "
        "whether the Gemini app may use Workspace apps, who has Gemini in Gmail, Docs and Drive, and how "
        "long conversation history is kept. Gemini in Gmail can be turned off in Generative AI > Gemini for "
        "Workspace > Feature access, but only on Enterprise and some Education editions; on other editions "
        "it follows each person's smart features setting, whose default an admin sets in Account > Account "
        f"settings > Smart features for Google Workspace. The full list is in {DOCS}checklist.md.",
    sources=["https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-google-apps-in-gemini-on-or-off",
             GEMINI_GMAIL_POST, GEMINI_FEATURE_ACCESS])


# ---------------------------------------------------------------- run

DRIVE_READONLY = "https://www.googleapis.com/auth/drive.readonly"

HINTS = {
    "disabled drive apps": " Your Drive settings block apps from using the Drive API (Admin console: Apps > "
                           "Google Workspace > Drive and Docs > Features and applications > Drive SDK). That is a "
                           "safe setting; the audit log check below still covers sharing.",
    "insufficient authentication scopes": " This check needs a permission the tool did not ask for.",
    "not authorized": " The account needs to be a super admin.",
    "access denied": " The account needs to be a super admin.",
}


def hint_for(message, status):
    low = (message or "").lower()
    for key, text in HINTS.items():
        if key in low:
            return text
    if status in (400, 403):
        return " This may need a super admin, or your Workspace edition may not include it."
    return ""


AFTERWARDS = ("When you are done, remove the tool's access: https://myaccount.google.com/permissions, find your "
              "OAuth client, Remove access. Delete the client in Google Cloud if you will not run the check again. "
              f"Details: {DOCS}setup-google.md#3-afterwards")


def run(client_file, days=180, max_files=5000, shared_drives=False, no_browser=False, keywords=None):
    token = sign_in(client_file, SCOPES + ([DRIVE_READONLY] if shared_drives else []), no_browser=no_browser)
    own = {load_client(client_file)["client_id"]}
    r = Result(platform="Google Workspace")
    try:
        me = get("https://openidconnect.googleapis.com/v1/userinfo", token)
        r.tenant = me.get("hd") or me.get("email", "")
        r.coverage.append(f"Signed in as {me.get('email', 'unknown')}.")
    except ApiError:
        pass

    def step(label, fn, key=None):
        print(f"  {label}...")
        try:
            fn()
        except ApiError as e:
            r.errors.append(f"{label}: {e.message.rstrip('.')}.{hint_for(e.message, e.status)}")
        else:
            if key and key not in r.checked:
                r.checked.append(key)

    def users():
        us = list(google_pages(f"{DIRECTORY}/users", token, {
            "customer": "my_customer", "maxResults": 500,
            "fields": "nextPageToken,users(primaryEmail,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,suspended,archived)"},
            "users"))
        for f in analyse_users(us):
            r.add(f)
        r.active_accounts = len(active_users(us))

    exposed = []

    def admin_view():
        by_vis = {}
        for vis in VIS:
            by_vis[vis] = list(google_pages(f"{DRIVE}/files", token, {
                "q": f"visibility = '{vis}' and trashed = false", "corpora": "allDrives",
                "includeItemsFromAllDrives": "true", "supportsAllDrives": "true", "pageSize": 1000,
                "fields": "nextPageToken,files(id,name,mimeType,modifiedTime,webViewLink,owners(emailAddress))"}, "files", limit=max_files))
        exposed.extend(files_from_drive(by_vis))
        r.coverage.append("Drive: files the signed-in admin can open (their own, shared drives they "
                          "belong to, and files shared with them), checked for link sharing. Other people's "
                          "files are seen only through the audit log below.")

    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def audit():
        acts = list(google_pages(f"{REPORTS}/drive", token, {
            "eventName": "change_document_visibility", "startTime": start, "maxResults": 1000}, "items", limit=20000))
        exposed.extend(files_from_audit(acts, {f["id"] for f in exposed}))
        r.coverage.append(f"Drive audit log: sharing changes by anyone in the organisation in the last "
                          f"{days} days. Files shared before that, and not visible to the admin, are not seen.")

    def tokens():
        acts = []
        for event in TOKEN_EVENTS:
            acts += google_pages(f"{REPORTS}/token", token, {
                "eventName": event, "startTime": start, "maxResults": 1000}, "items", limit=20000)
        for f in analyse_tokens(acts, own):
            r.add(f)
        r.coverage.append(f"Connected apps: apps staff authorised in the last {days} days (token audit log), "
                          "leaving out apps each person's access was revoked for afterwards. Apps an admin "
                          "blocked for the whole organisation in App access control may still be listed: "
                          "Google logs that block in the admin log, not as a revoke in the token log. Apps "
                          "authorised before then are not seen.")

    def drives():
        ds = list(google_pages(f"{DRIVE}/drives", token, {
            "useDomainAdminAccess": "true", "pageSize": 100,
            "fields": "nextPageToken,drives(id,name,restrictions)"}, "drives"))
        for f in analyse_shared_drives(ds):
            r.add(f)

    step("Accounts and 2-step verification", users, "accounts")
    step("Files shared by link (admin view)", admin_view, "files")
    step("Sharing changes in the audit log", audit, "files")
    step("Connected apps", tokens, "apps")
    if shared_drives:
        step("Shared drive settings", drives)
    else:
        r.coverage.append("Shared drive settings were not checked: that needs the wider Drive read "
                          "permission. Run with --shared-drives to include them.")
    for f in exposure.findings(exposed, "gws", keywords):
        r.add(f)
    r.summary = exposure.summary(exposed, keywords)
    r.add(GEMINI_MANUAL)
    r.coverage.append("Only names and settings were read. No file contents were opened.")
    r.finished = now()
    return r
