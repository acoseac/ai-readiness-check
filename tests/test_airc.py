import hashlib
import base64
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from airc import auth, demo, exposure, google_ws, http, m365, report
from airc.__main__ import build_parser
from airc.patterns import OWN_WORDS, compile_terms, fold, hints, looks_like_ai_app, read_terms


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Patterns(unittest.TestCase):
    def test_sensitive_names(self):
        self.assertEqual(hints("Beneficiary_list_2026.xlsx"), ["beneficiaries and protection"])
        self.assertEqual(hints("Liste des bénéficiaires.csv"), ["beneficiaries and protection"])
        self.assertEqual(hints("Passport scans"), ["identity documents"])
        self.assertEqual(hints("salaires-2026.xlsx"), ["staff and pay"])
        self.assertIn("beneficiaries and protection", hints("GBV case notes.docx"))
        self.assertEqual(hints("Titre de séjour copies.pdf"), ["identity documents"])
        self.assertEqual(hints("IBAN fournisseurs.xlsx"), ["finance and donors"])
        self.assertEqual(hints("Lista de beneficiarios 2026.xlsx"), ["beneficiaries and protection"])
        self.assertEqual(hints("Pasaportes escaneados"), ["identity documents"])
        self.assertEqual(hints("Nómina octubre.xlsx"), ["staff and pay"])
        self.assertEqual(hints("قائمة المستفيدين.xlsx"), ["beneficiaries and protection"])
        self.assertEqual(hints("جوازات السفر"), ["identity documents"])
        self.assertEqual(hints("رواتب 2026"), ["staff and pay"])
        self.assertEqual(hints("Meeting started 2026/06/17 18:31 CEST - Notes by Gemini"),
                         ["meeting notes and transcripts"])

    def test_ordinary_names(self):
        for name in ("Budget 2026.xlsx", "Team lunch menu.txt", "Annual report draft.docx", "Informe anual.docx",
                     "خطة العمل", 
                     "Photos workshop", "Shared calendar", "Chairs.xlsx", "Hrvatska trip.pdf"):
            self.assertEqual(hints(name), [], name)

    def test_fold(self):
        self.assertEqual(fold("Dossier_Médical-(copie).PDF"), "dossier medical copie pdf")

    def test_ai_apps(self):
        for name in ("Otter.ai", "Fireflies.ai Meeting Notes", "ChatGPT", "Read AI", "Claude"):
            self.assertTrue(looks_like_ai_app(name), name)
        for name in ("Zoom", "Slack", "Dropbox", "Mailchimp", "Airtable"):
            self.assertFalse(looks_like_ai_app(name), name)


    def test_own_keywords(self):
        rx = compile_terms(["Projet Soleil", "donor", "  ", "mot-clé"])
        self.assertEqual(hints("projet_soleil_budget.xlsx", rx), [OWN_WORDS])
        self.assertEqual(hints("Donors 2026.xlsx", rx), [OWN_WORDS])  # matched at the start of a word
        self.assertEqual(hints("Mot clé list", rx), [OWN_WORDS])  # folded like file names
        self.assertEqual(hints("Condor photos", rx), [])
        self.assertEqual(hints("bbbc draft", compile_terms(["b*c"])), [])  # escaped, not a pattern
        self.assertEqual(hints("a.b*c draft", compile_terms(["b*c"])), [OWN_WORDS])
        self.assertIsNone(compile_terms(["", "  "]))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "words.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# our programmes\nProjet Soleil\n\nمشروع الأمل\n")
            self.assertEqual(read_terms(path), ["Projet Soleil", "مشروع الأمل"])
            self.assertEqual(hints("مشروع الأمل 2026.xlsx", compile_terms(read_terms(path))), [OWN_WORDS])


class Exposure(unittest.TestCase):
    def test_grouping_and_severity(self):
        fs = exposure.findings([
            {"name": "Beneficiary list.xlsx", "exposure": "anyone"},
            {"name": "Menu.txt", "exposure": "anyone"},
            {"name": "Salary 2026.xlsx", "exposure": "domain"},
            {"name": "Notes", "exposure": "domain"},
        ], "t")
        sev = {f.id: f.severity for f in fs}
        self.assertEqual(sev["t-share-anyone-sensitive"], "high")
        self.assertEqual(sev["t-share-anyone-other"], "medium")
        self.assertEqual(sev["t-share-domain-sensitive"], "medium")
        self.assertEqual(sev["t-share-domain-other"], "low")

    def test_folders_open_to_anyone_are_fix_first(self):
        fs = {f.id: f for f in exposure.findings([
            {"name": "Workshop photos", "kind": "folder", "exposure": "anyone"},
            {"name": "Menu.txt", "exposure": "anyone"},
            {"name": "Old stuff", "kind": "folder", "exposure": "domain"},
        ], "gws")}
        self.assertEqual(fs["gws-share-anyone-folder"].severity, "high")
        self.assertEqual([i["name"] for i in fs["gws-share-anyone-other"].items], ["Menu.txt"])
        self.assertEqual(fs["gws-share-domain-other"].severity, "low")

    def test_sort_folders_then_recent(self):
        f = exposure.findings([
            {"name": "b old", "exposure": "anyone", "modified": "2024-01-01"},
            {"name": "a undated", "exposure": "anyone"},
            {"name": "c new", "exposure": "anyone", "modified": "2026-11-01"},
            {"name": "z folder", "kind": "folder", "exposure": "anyone", "hints": ["health"]},
            {"name": "y file", "exposure": "anyone", "hints": ["health"], "modified": "2026-01-01"},
        ], "m365")
        other = next(x for x in f if x.id == "m365-share-anyone-other")
        self.assertEqual([i["name"] for i in other.items], ["c new", "b old", "a undated"])
        self.assertEqual(other.items[0]["changed"], "2026-11-01")
        sens = next(x for x in f if x.id == "m365-share-anyone-sensitive")
        self.assertEqual([i["name"] for i in sens.items], ["z folder [folder]", "y file"])

    def test_platform_fix_texts(self):
        g = exposure.findings([{"name": "x", "exposure": "anyone"}], "gws")[0]
        m = exposure.findings([{"name": "x", "exposure": "anyone"}], "m365")[0]
        self.assertIn("Restricted", g.fix)
        self.assertNotIn("expir", g.fix.replace("end date", ""))  # Drive cannot expire Anyone links
        self.assertIn("expires", m.fix)
        self.assertIn("Tell the owner first", m.fix)
        self.assertTrue(g.sources and m.sources)

    def test_keywords_reach_findings(self):
        fs = exposure.findings([{"name": "Projet Soleil.xlsx", "exposure": "domain"}], "gws",
                               compile_terms(["projet soleil"]))
        self.assertEqual(fs[0].id, "gws-share-domain-sensitive")
        self.assertEqual(fs[0].items[0]["looks like"], OWN_WORDS)

    def test_summary_is_never_an_all_clear(self):
        s = exposure.summary([{"name": "Export final v3.xlsx", "exposure": "anyone"},
                              {"name": "Menu", "exposure": "domain"}, {"name": "Menu 2", "exposure": "domain"}])
        self.assertTrue(s.startswith("1 items open to anyone with the link, 2 to the whole organisation and 0"))
        self.assertIn("0 of them have names that matched", s)
        self.assertIn("not an all-clear", s)
        self.assertIn("not an all-clear", exposure.summary([]))


class Auth(unittest.TestCase):
    def test_pkce_and_url(self):
        verifier, challenge = auth.pkce_pair()
        expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(challenge, expected)
        self.assertGreaterEqual(len(verifier), 43)
        url = auth.authorize_url("https://login.microsoftonline.com/x/oauth2/v2.0/authorize", "cid",
                                 "http://localhost:5000", "a b", "st", challenge, {"prompt": "select_account"})
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual(q["redirect_uri"], ["http://localhost:5000"])
        self.assertEqual((q["state"], q["scope"], q["prompt"]), (["st"], ["a b"], ["select_account"]))

    def test_redirect_checks(self):
        self.assertEqual(auth.read_redirect({"state": "s", "code": "c"}, "s"), "c")
        with self.assertRaisesRegex(auth.SignInError, "state"):
            auth.read_redirect({"state": "other", "code": "c"}, "s")
        with self.assertRaisesRegex(auth.SignInError, "AADSTS65004"):
            auth.read_redirect({"state": "s", "error": "access_denied",
                                "error_description": "AADSTS65004: User declined to consent"}, "s")
        with self.assertRaisesRegex(auth.SignInError, "no sign-in code"):
            auth.read_redirect({"state": "s"}, "s")

    def test_paste_back(self):
        addr = "http://127.0.0.1:49152/?state=s1&code=4/0Abc-d_e&scope=email%20openid"
        self.assertEqual(auth.parse_pasted("  '" + addr + "'\n", "s1"), "4/0Abc-d_e")
        self.assertEqual(auth.parse_pasted("state=s1&code=xyz", "s1"), "xyz")
        self.assertEqual(auth.parse_pasted(addr + "#frag", "s1"), "4/0Abc-d_e")
        with self.assertRaises(auth.SignInError):
            auth.parse_pasted(addr, "s2")
        with self.assertRaises(auth.SignInError):
            auth.parse_pasted("", "s1")

    def test_paste_mode_never_listens(self):
        seen = {}

        def reader(prompt):
            url = seen["url"]
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            return f"{q['redirect_uri'][0]}/?state={q['state'][0]}&code=pasted"

        code, redirect, verifier = auth.browser_code(
            "https://accounts.google.com/o/oauth2/auth", "cid", "email", paste=True, reader=reader,
            opener=lambda u: self.fail("no browser in paste mode"),
            out=lambda text: seen.setdefault("url", text.split("\n\n")[1]) if "\n\n" in text else None)
        self.assertEqual(code, "pasted")
        self.assertTrue(redirect.startswith("http://127.0.0.1:"))
        self.assertTrue(verifier)

    def test_loopback_flow(self):
        def fake_browser(url):
            q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
            base = q["redirect_uri"].replace("localhost", "127.0.0.1")

            def visit():
                for path in ("/favicon.ico", f"/?state=wrong&code=evil", f"/?state={q['state']}&code=good"):
                    try:
                        with urllib.request.urlopen(base + path, timeout=5) as resp:
                            resp.read()
                    except urllib.error.HTTPError as e:
                        e.close()
            threading.Thread(target=visit, daemon=True).start()

        code, redirect, _ = auth.browser_code("https://login.microsoftonline.com/t/oauth2/v2.0/authorize", "cid",
                                              "scope", host="localhost", opener=fake_browser, timeout=10,
                                              out=lambda *_: None)
        self.assertEqual(code, "good")
        self.assertTrue(redirect.startswith("http://localhost:"))

    def test_loopback_reports_error_redirect(self):
        def fake_browser(url):
            q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}

            def visit():
                with urllib.request.urlopen(f"{q['redirect_uri']}/?state={q['state']}&error=access_denied"
                                            "&error_description=declined", timeout=5) as resp:
                    resp.read()
            threading.Thread(target=visit, daemon=True).start()

        with self.assertRaisesRegex(auth.SignInError, "declined"):
            auth.browser_code("https://accounts.google.com/o/oauth2/auth", "cid", "email",
                              opener=fake_browser, timeout=10, out=lambda *_: None)


class Http(unittest.TestCase):
    def test_allowlist(self):
        for ok in ("https://graph.microsoft.com/v1.0/sites", "https://login.microsoftonline.com/x/oauth2/v2.0/token",
                   "https://admin.googleapis.com/admin/directory/v1/users", "https://oauth2.googleapis.com/token",
                   "https://accounts.google.com/o/oauth2/auth", "https://www.googleapis.com/drive/v3/files"):
            self.assertEqual(http.check_url(ok), ok)
        for bad in ("http://graph.microsoft.com/v1.0/sites", "https://graph.microsoft.com.evil.example/x",
                    "https://evilgoogleapis.com/x", "https://user@graph.microsoft.com/x",
                    "https://graph.microsoft.com:8443/x", "https://example.org/", "file:///etc/passwd", ""):
            with self.assertRaises(http.HostNotAllowed, msg=bad):
                http.check_url(bad)

    def test_token_never_leaves_for_other_hosts(self):
        # A paging link pointing elsewhere is refused before any request is made.
        with self.assertRaises(http.HostNotAllowed):
            http.get("https://collector.example/next?page=2", "secret-token")
        with self.assertRaises(http.HostNotAllowed):
            http.post_form("https://collector.example/token", {"code": "x"})

    def test_google_client_file_hosts_checked(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "client.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"installed": {"client_id": "x", "token_uri": "https://collector.example/token"}}, fh)
            with self.assertRaises(SystemExit):
                google_ws.load_client(path)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"installed": {"client_id": "x"}}, fh)
            self.assertEqual(google_ws.load_client(path)["token_uri"], "https://oauth2.googleapis.com/token")


class ReadOnly(unittest.TestCase):
    def test_only_read_scopes(self):
        self.assertNotIn("User.Read.All", m365.SCOPES)
        for scope in m365.SCOPES + google_ws.SCOPES + [google_ws.DRIVE_READONLY]:
            self.assertNotRegex(scope.lower(), r"write|manage|send|fullcontrol", scope)
            if scope.startswith("https://www.googleapis.com/auth/"):
                self.assertTrue(scope.endswith("readonly"), scope)
            elif "." in scope:
                self.assertIn(".Read", scope)

    def test_cli_options(self):
        a = build_parser().parse_args(["m365", "--no-browser", "--keywords", "w.txt"])
        self.assertTrue(a.no_browser)
        self.assertEqual(a.keywords, "w.txt")
        a = build_parser().parse_args(["google", "--client", "c.json", "--no-browser"])
        self.assertTrue(a.no_browser)


class Google(unittest.TestCase):
    def test_users(self):
        fs = google_ws.analyse_users([
            {"primaryEmail": "a@x", "isAdmin": True, "isEnrolledIn2Sv": False},
            {"primaryEmail": "b@x", "isEnrolledIn2Sv": False},
            {"primaryEmail": "c@x", "isEnrolledIn2Sv": False, "suspended": True},
        ])
        ids = {f.id: f for f in fs}
        self.assertEqual(ids["gws-admin-2sv"].severity, "high")
        self.assertEqual([i["name"] for i in ids["gws-user-2sv"].items], ["b@x"])

    def test_google_ai_and_devices(self):
        def act(name, who="a@x", scopes=("https://mail.google.com/",)):
            return {"actor": {"email": who}, "id": {"time": "2026-11-01T00:00:00Z"}, "events": [{
                "name": "authorize", "parameters": [{"name": "app_name", "value": name},
                                                    {"name": "client_id", "value": name + who},
                                                    {"name": "scope", "multiValue": list(scopes)}]}]}
        fs = {f.id: f for f in google_ws.analyse_tokens(
            [act("Gemini Business"), act("macOS"), act("iOS"), act("Claude"), act("Claude", "b@x"),
             act("AI readiness check")], own_client_ids={"AI readiness checka@x"})}
        self.assertEqual(set(fs), {"gws-apps-google-ai", "gws-apps-ai"})
        self.assertEqual(fs["gws-apps-google-ai"].severity, "info")
        self.assertEqual([(i["name"], i["people"]) for i in fs["gws-apps-ai"].items], [("Claude", 2)])

    def test_hints(self):
        self.assertIn("Drive SDK", google_ws.hint_for("The domain administrators have disabled Drive apps.", 403))
        self.assertIn("permission", google_ws.hint_for("Request had insufficient authentication scopes.", 403))

    def test_audit_keeps_latest_and_skips_private(self):
        def ev(doc, vis, t):
            return {"id": {"time": t}, "events": [{"name": "change_document_visibility", "parameters": [
                {"name": "doc_id", "value": doc}, {"name": "doc_title", "value": doc + " title"},
                {"name": "visibility", "value": vis}]}]}
        # newest first, as the Reports API returns them
        acts = [ev("A", "private", "2026-11-02T00:00:00Z"), ev("A", "people_with_link", "2026-10-01T00:00:00Z"),
                ev("B", "people_within_domain_with_link", "2026-10-05T00:00:00Z"),
                ev("C", "people_with_link", "2026-10-06T00:00:00Z")]
        files = google_ws.files_from_audit(acts, known_ids={"C"})
        self.assertEqual([(f["id"], f["exposure"]) for f in files], [("B", "domain")])

    def test_tokens(self):
        acts = [{"actor": {"email": "a@x"}, "id": {"time": "2026-11-01T00:00:00Z"}, "events": [{
            "name": "authorize", "parameters": [{"name": "app_name", "value": "Otter.ai"},
                                                {"name": "client_id", "value": "1"},
                                                {"name": "scope", "multiValue": ["https://mail.google.com/"]}]}]},
                {"actor": {"email": "b@x"}, "id": {"time": "2026-11-01T00:00:00Z"}, "events": [{
                    "name": "authorize", "parameters": [{"name": "app_name", "value": "Google Chrome"},
                                                        {"name": "client_id", "value": "2"},
                                                        {"name": "scope", "multiValue": ["https://mail.google.com/"]}]}]}]
        fs = google_ws.analyse_tokens(acts)
        self.assertEqual([f.id for f in fs], ["gws-apps-ai"])
        self.assertEqual(fs[0].items[0]["access"], "mail")


class Microsoft(unittest.TestCase):
    def test_permission_exposure(self):
        d = ["ngo.example"]
        self.assertEqual(m365.permission_exposure([{"link": {"scope": "anonymous"}}], d), "anyone")
        self.assertEqual(m365.permission_exposure([{"link": {"scope": "organization"}}], d), "domain")
        self.assertEqual(m365.permission_exposure(
            [{"grantedToV2": {"siteGroup": {"displayName": "Everyone except external users"}}}], d), "domain")
        self.assertEqual(m365.permission_exposure(
            [{"grantedToV2": {"user": {"email": "x@partner.example"}}}], d), "external")
        self.assertEqual(m365.permission_exposure(
            [{"grantedToV2": {"user": {"email": "x_partner.example#EXT#@ngo.example"}}}], d), "external")
        self.assertIsNone(m365.permission_exposure(
            [{"grantedToV2": {"user": {"email": "me@NGO.example"}}}], d))
        self.assertIsNone(m365.permission_exposure(
            [{"grantedToV2": {"user": {"email": "x@partner.example"}}}], []))

    def test_mfa(self):
        self.assertEqual(m365.analyse_mfa({"isEnabled": True}, None).severity, "info")
        self.assertEqual(m365.analyse_mfa({"isEnabled": False}, None).severity, "high")
        ca = [{"displayName": "All users MFA", "state": "enabled", "grantControls": {"builtInControls": ["mfa"]}},
              {"displayName": "Report only", "state": "enabledForReportingButNotEnforced",
               "grantControls": {"builtInControls": ["mfa"]}}]
        f = m365.analyse_mfa({"isEnabled": False}, ca)
        self.assertEqual((f.id, len(f.items)), ("m365-mfa-ca", 1))

    def test_consent(self):
        legacy = {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [
            "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}
        self.assertEqual(m365.analyse_consent_policy(legacy).severity, "high")
        self.assertEqual(m365.analyse_consent_policy({}).id, "m365-user-consent-none")
        managed = {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [
            "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team",
            "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"]}}
        self.assertEqual(m365.analyse_consent_policy(managed).id, "m365-user-consent-other")

    def test_skus(self):
        f = m365.analyse_skus([{"skuPartNumber": "Microsoft_365_Copilot", "consumedUnits": 2},
                               {"skuPartNumber": "Microsoft_Copilot_for_Sales", "consumedUnits": 5}])
        self.assertEqual(f.id, "m365-copilot-licences")
        self.assertIn("2 Microsoft 365 Copilot", f.title)
        self.assertIn("Data access governance", f.fix)
        self.assertTrue(any("not counted" in i.get("note", "") for i in f.items))
        # bought but not assigned, or only other Copilot-named products: no pointer to SAM reports
        for skus in ([{"skuPartNumber": "Microsoft_365_Copilot", "consumedUnits": 0}],
                     [{"skuPartNumber": "Microsoft_Copilot_for_Sales", "consumedUnits": 5}], []):
            f = m365.analyse_skus(skus)
            self.assertEqual(f.id, "m365-copilot-none")
            self.assertNotIn("Data access governance", f.fix)
            self.assertIn("Microsoft Graph", f.why)

    def test_device_code(self):
        self.assertIsNone(m365.analyse_device_code(None))
        block = {"displayName": "Block device code", "state": "enabled",
                 "conditions": {"users": {"includeUsers": ["All"]},
                                "authenticationFlows": {"transferMethods": "deviceCodeFlow,authenticationTransfer"}},
                 "grantControls": {"builtInControls": ["block"]}}
        self.assertEqual(m365.analyse_device_code([block]).id, "m365-device-code-blocked")
        report_only = dict(block, state="enabledForReportingButNotEnforced")
        self.assertEqual(m365.analyse_device_code([report_only]).id, "m365-device-code-open")
        some = dict(block, conditions=dict(block["conditions"], users={"includeUsers": ["group-id"]}))
        f = m365.analyse_device_code([some])
        self.assertEqual((f.id, f.severity, len(f.items)), ("m365-device-code-open", "low", 1))
        transfer_only = dict(block, conditions=dict(block["conditions"],
                                                    authenticationFlows={"transferMethods": "authenticationTransfer"}))
        self.assertEqual(m365.analyse_device_code([transfer_only]).id, "m365-device-code-open")
        self.assertEqual(m365.analyse_device_code([]).id, "m365-device-code-open")

    def test_coverage_states_limits(self):
        text = m365.sharepoint_coverage(3, 50, 900, 3000, 3000, 2)
        for part in ("limit 3000, reached", "first 200 files", "member or owner", "owners", "Personal OneDrives"):
            self.assertIn(part, text)
        self.assertNotIn("first 200", m365.sharepoint_coverage(3, 50, 900, 10, 3000, 0))

    def test_grants_skip_microsoft(self):
        sps = {"a": {"displayName": "Teams", "appOwnerOrganizationId": next(iter(m365.MICROSOFT_TENANTS))},
               "b": {"displayName": "Fathom", "appOwnerOrganizationId": "z"}}
        fs = m365.analyse_grants([{"clientId": "a", "scope": "Mail.Read"},
                                  {"clientId": "b", "consentType": "Principal", "scope": "Calendars.Read"}], sps)
        self.assertEqual([f.id for f in fs], ["m365-apps-ai"])
        self.assertEqual(fs[0].items[0]["granted for"], "1 person")
        own = m365.analyse_grants([{"clientId": "c", "consentType": "AllPrincipals", "scope": "Sites.Read.All"}],
                                  {"c": {"appId": m365.DEFAULT_CLIENT_ID, "displayName": "Microsoft Graph Command Line Tools"}},
                                  own_app_id=m365.DEFAULT_CLIENT_ID)
        self.assertEqual(own, [])


class FakeRuns(unittest.TestCase):
    """Whole runs against fake API answers: no sign-in, no network."""

    def patch(self, module, **fakes):
        for name, fake in fakes.items():
            old = getattr(module, name)
            setattr(module, name, fake)
            self.addCleanup(setattr, module, name, old)

    def test_m365_run(self):
        answers = {
            "/organization": {"value": [{"displayName": "NGO", "verifiedDomains": [{"name": "ngo.example"}]}]},
            "/me": {"userPrincipalName": "admin@ngo.example"},
            "/admin/sharepoint/settings": {"sharingCapability": "externalUserAndGuestSharing"},
            "/policies/authorizationPolicy": {},
            "/policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
            "/users": {"@odata.count": 2},
        }
        pages = {
            "/oauth2PermissionGrants": [], "/subscribedSkus": [],
            "/identity/conditionalAccess/policies": [],
            "/sites": [{"id": "s1", "displayName": "Programmes"}],
            "/sites/s1/drives": [{"id": "d1"}],
            "/drives/d1/root/delta": [
                {"id": "i1", "name": "Export final v3.xlsx", "file": {}, "shared": {"scope": "anonymous"},
                 "lastModifiedDateTime": "2026-11-02T10:00:00Z", "parentReference": {"path": "/drive/root:/Data"}},
                {"id": "i2", "name": "Photos", "folder": {"childCount": 3}, "shared": {"scope": "anonymous"}}],
            "/drives/d1/items/i1/permissions": [{"link": {"scope": "anonymous"}}],
            "/drives/d1/items/i2/permissions": [{"link": {"scope": "anonymous"}}],
        }

        def key(url):
            return url.split("/v1.0", 1)[1]

        self.patch(m365, sign_in=lambda *a, **k: "token",
                   get=lambda url, token, params=None, headers=None: answers[key(url)],
                   graph_pages=lambda url, token, params=None, headers=None, limit=None: iter(pages[key(url)]))
        with contextlib.redirect_stdout(io.StringIO()):
            r = m365.run(keywords=compile_terms(["export"]))
        ids = {f.id: f for f in r.findings}
        self.assertEqual(r.errors, [])
        self.assertIn("m365-share-anyone-folder", ids)
        self.assertEqual(ids["m365-share-anyone-sensitive"].items[0]["changed"], "2026-11-02")
        self.assertEqual(ids["m365-share-anyone-sensitive"].items[0]["looks like"], OWN_WORDS)
        self.assertIn("m365-device-code-open", ids)
        self.assertIn("m365-copilot-none", ids)
        self.assertTrue(r.summary.startswith("2 items open to anyone"))
        self.assertTrue(any("member or owner" in c for c in r.coverage))

    def test_google_run(self):
        def pages(url, token, params, key, limit=None):
            if url.endswith("/users"):
                return iter([{"primaryEmail": "a@ngo.example", "isAdmin": True, "isEnrolledIn2Sv": True}])
            if url.endswith("/files"):
                self.assertIn("modifiedTime", params["fields"])
                if params["q"].startswith("visibility = 'anyoneWithLink'"):
                    return iter([{"id": "f1", "name": "Export final v3.xlsx", "modifiedTime": "2026-10-01T00:00:00Z"}])
            return iter([])

        with tempfile.TemporaryDirectory() as d:
            client = os.path.join(d, "client.json")
            with open(client, "w", encoding="utf-8") as fh:
                json.dump({"installed": {"client_id": "own-client"}}, fh)
            self.patch(google_ws, sign_in=lambda *a, **k: "token", google_pages=pages,
                       get=lambda url, token, params=None: {"email": "a@ngo.example", "hd": "ngo.example"})
            with contextlib.redirect_stdout(io.StringIO()):
                r = google_ws.run(client)
        ids = {f.id: f for f in r.findings}
        self.assertEqual(r.errors, [])
        self.assertEqual(ids["gws-share-anyone-other"].items[0]["changed"], "2026-10-01")
        self.assertIn("not read Gemini settings", ids["gws-gemini-manual"].why)
        self.assertIn("0 of them have names", r.summary)


class Report(unittest.TestCase):
    def test_demo_report(self):
        results = demo.run()
        with tempfile.TemporaryDirectory() as d:
            paths = report.write(results, d)
            md, html, raw = (read(paths[k]) for k in ("report.md", "report.html", "findings.json"))
            data = json.loads(raw)
            self.assertIn("Fix first", md)
            self.assertIn("<a href='https://drive.google.com/open?id=1'", html)
            self.assertIn("<!doctype html>", html)
            self.assertEqual(len(data), 2)
            self.assertEqual(oct(os.stat(paths["report.md"]).st_mode & 0o777), "0o600")
            for text in (md, html):
                self.assertNotIn("—", text)
                self.assertNotIn("–", text)
                # the summary and what was seen come before the first finding
                self.assertLess(text.index("Shared most widely"), text.index("Fix first:" if text is md else "class='f'"))
                self.assertLess(text.index("What this run could and could not see"),
                                text.index("Fix first:" if text is md else "class='f'"))
                self.assertIn("Fixing it without breaking daily work", text)
                self.assertIn("https://github.com/acoseac/ai-readiness-check/blob/main/docs/checklist.md", text)
            self.assertIn("Export final v3.xlsx", md)
            self.assertIn("<a href='https://learn.microsoft.com/en-us/sharepoint/restricted-content-discovery'", html)
            self.assertNotIn("](docs/", md)

    def test_html_escapes(self):
        from airc.findings import Finding, Result
        r = Result(platform="Test")
        r.add(Finding(id="x", severity="low", title="t", why="w", fix="f", items=[{"name": "<script>x</script>"}]))
        self.assertNotIn("<script>x", report.to_html([r]))


if __name__ == "__main__":
    unittest.main()
