"""Google Workspace check. Read-only: it asks Google only for read-only scopes and only sends
GET requests for data. Sign-in uses your own OAuth client (see docs/setup-google.md) and a
local browser redirect; no token is saved to disk."""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

from . import exposure
from .findings import Finding, Result, now
from .http import ApiError, get, google_pages, post_form
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

def sign_in(client_file, scopes=SCOPES, timeout=300):
    with open(client_file, encoding="utf-8") as fh:
        cfg = json.load(fh)
    c = cfg.get("installed") or cfg.get("web")
    if not c or "client_id" not in c:
        raise SystemExit("That file does not look like a Google OAuth client (Desktop app). "
                         "See docs/setup-google.md.")
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    got = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("state", [None])[0] != state:
                self.send_response(404)
                self.end_headers()
                return
            got["code"] = q.get("code", [None])[0]
            got["error"] = q.get("error", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<p>Signed in. You can close this tab and go back to the terminal.</p>")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 5
    redirect = f"http://127.0.0.1:{server.server_port}"
    url = c.get("auth_uri", "https://accounts.google.com/o/oauth2/auth") + "?" + urllib.parse.urlencode({
        "client_id": c["client_id"], "redirect_uri": redirect, "response_type": "code",
        "scope": " ".join(scopes), "code_challenge": challenge, "code_challenge_method": "S256",
        "state": state, "access_type": "online", "prompt": "consent",
    })
    print("Sign in with a Google Workspace super admin account in the browser window.")
    print(f"If no window opens, paste this address into a browser:\n{url}\n")
    webbrowser.open(url)
    deadline = time.time() + timeout
    while not got and time.time() < deadline:
        server.handle_request()
    server.server_close()
    if not got.get("code"):
        raise SystemExit(f"Sign-in did not complete ({got.get('error') or 'timed out'}).")
    tok = post_form(c.get("token_uri", "https://oauth2.googleapis.com/token"), {
        "code": got["code"], "client_id": c["client_id"], "client_secret": c.get("client_secret", ""),
        "redirect_uri": redirect, "grant_type": "authorization_code", "code_verifier": verifier,
    })
    if "access_token" not in tok:
        raise SystemExit(f"Sign-in failed: {tok.get('error_description') or tok.get('error')}")
    return tok["access_token"]


# ---------------------------------------------------------------- analysis (pure, tested)

def analyse_users(users):
    active = [u for u in users if not u.get("suspended") and not u.get("archived")]
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
                        "seen": "admin view"})
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
                    "owner": p.get("owner", ""), "seen": f"audit log, changed {when}"})
    return out


GMAIL = {"https://mail.google.com/", "https://www.googleapis.com/auth/gmail.readonly",
         "https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.metadata"}
DRIVE_ALL = {"https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.readonly"}
CAL = {"https://www.googleapis.com/auth/calendar", "https://www.googleapis.com/auth/calendar.readonly",
       "https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/calendar.events.readonly"}
FIRST_PARTY = ("google ", "android", "chrome", "gmail", "my google")


def analyse_tokens(activities):
    apps = {}
    for act in activities:
        who = (act.get("actor") or {}).get("email", "")
        when = (act.get("id") or {}).get("time", "")[:10]
        for ev in act.get("events", []) or []:
            if ev.get("name") != "authorize":
                continue
            p = _params(ev)
            cid = p.get("client_id") or p.get("app_name")
            a = apps.setdefault(cid, {"name": p.get("app_name") or cid, "users": set(), "scopes": set(), "last": ""})
            a["users"].add(who)
            sc = p.get("scope") or []
            a["scopes"].update(sc if isinstance(sc, list) else [sc])
            a["last"] = max(a["last"], when)
    ai, broad = [], []
    for a in apps.values():
        if a["name"].lower().startswith(FIRST_PARTY):
            continue
        access = [label for label, s in (("mail", GMAIL), ("all files", DRIVE_ALL), ("calendar", CAL))
                  if a["scopes"] & s]
        item = {"name": a["name"], "people": len(a["users"]), "access": ", ".join(access), "last": a["last"]}
        if looks_like_ai_app(a["name"]):
            ai.append(item)
        elif access:
            broad.append(item)
    out = []
    if ai:
        out.append(Finding(
            id="gws-apps-ai", severity="medium", title=f"AI and meeting-note apps connected by staff ({len(ai)})",
            why="These apps were given access to staff accounts. Meeting bots join calls and keep "
                "transcripts; AI apps may store or learn from what they read, outside your control.",
            fix="For each one, decide whether it is allowed. Remove the ones that are not (Security > "
                "Access and data control > API controls > App access control), and limit which "
                "apps staff can connect.",
            items=sorted(ai, key=lambda i: -i["people"])))
    if broad:
        out.append(Finding(
            id="gws-apps-broad", severity="low", title=f"Other apps with access to mail, all files or calendars ({len(broad)})",
            why="Any connected app can read what it was granted. Old or unknown ones are a quiet way out for data.",
            fix="Remove apps nobody uses, and review the list every few months.",
            items=sorted(broad, key=lambda i: -i["people"])))
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


GEMINI_MANUAL = Finding(
    id="gws-gemini-manual", severity="info", title="Gemini settings need a look by hand",
    why="Google does not expose most Gemini settings to read-only tools, so this check cannot see them.",
    fix="In the Admin console, open Generative AI and check who can use the Gemini app, NotebookLM "
        "and Gemini in Gmail, Docs and Drive, and whether conversation history is kept. The full "
        "list is in docs/checklist.md.")


# ---------------------------------------------------------------- run

def run(client_file, days=180, max_files=5000):
    token = sign_in(client_file)
    r = Result(platform="Google Workspace")
    try:
        me = get("https://openidconnect.googleapis.com/v1/userinfo", token)
        r.tenant = me.get("hd") or me.get("email", "")
        r.coverage.append(f"Signed in as {me.get('email', 'unknown')}.")
    except ApiError:
        pass

    def step(label, fn):
        print(f"  {label}...")
        try:
            fn()
        except ApiError as e:
            hint = " (this needs a super admin, or the Workspace edition may not include it)" if e.status in (400, 403) else ""
            r.errors.append(f"{label}: {e.message}{hint}")

    def users():
        us = list(google_pages(f"{DIRECTORY}/users", token, {
            "customer": "my_customer", "maxResults": 500,
            "fields": "nextPageToken,users(primaryEmail,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,suspended,archived)"},
            "users"))
        for f in analyse_users(us):
            r.add(f)

    exposed = []

    def admin_view():
        by_vis = {}
        for vis in VIS:
            by_vis[vis] = list(google_pages(f"{DRIVE}/files", token, {
                "q": f"visibility = '{vis}' and trashed = false", "corpora": "allDrives",
                "includeItemsFromAllDrives": "true", "supportsAllDrives": "true", "pageSize": 1000,
                "fields": "nextPageToken,files(id,name,mimeType,owners(emailAddress))"}, "files", limit=max_files))
        exposed.extend(files_from_drive(by_vis))
        r.coverage.append("Drive: files the signed-in admin can open (their own, shared drives they "
                          "belong to, and files shared with them), checked for link sharing.")

    start = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def audit():
        acts = list(google_pages(f"{REPORTS}/drive", token, {
            "eventName": "change_document_visibility", "startTime": start, "maxResults": 1000}, "items", limit=20000))
        exposed.extend(files_from_audit(acts, {f["id"] for f in exposed}))
        r.coverage.append(f"Drive audit log: sharing changes by anyone in the organisation in the last "
                          f"{days} days. Files shared before that, and not visible to the admin, are not seen.")

    def tokens():
        acts = list(google_pages(f"{REPORTS}/token", token, {
            "eventName": "authorize", "startTime": start, "maxResults": 1000}, "items", limit=20000))
        for f in analyse_tokens(acts):
            r.add(f)
        r.coverage.append(f"Connected apps: apps staff authorised in the last {days} days (token audit log).")

    def drives():
        ds = list(google_pages(f"{DRIVE}/drives", token, {
            "useDomainAdminAccess": "true", "pageSize": 100,
            "fields": "nextPageToken,drives(id,name,restrictions)"}, "drives"))
        for f in analyse_shared_drives(ds):
            r.add(f)

    step("Accounts and 2-step verification", users)
    step("Files shared by link (admin view)", admin_view)
    step("Sharing changes in the audit log", audit)
    step("Connected apps", tokens)
    step("Shared drive settings", drives)
    for f in exposure.findings(exposed, "gws"):
        r.add(f)
    r.add(GEMINI_MANUAL)
    r.coverage.append("Only names and settings were read. No file contents were opened.")
    r.finished = now()
    return r
