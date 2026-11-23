import json
import os
import tempfile
import unittest

from airc import demo, exposure, google_ws, m365, report
from airc.patterns import fold, hints, looks_like_ai_app


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

    def test_ordinary_names(self):
        for name in ("Budget 2026.xlsx", "Team lunch menu.txt", "Annual report draft.docx",
                     "Photos workshop", "Shared calendar", "Chairs.xlsx", "Hrvatska trip.pdf"):
            self.assertEqual(hints(name), [], name)

    def test_fold(self):
        self.assertEqual(fold("Dossier_Médical-(copie).PDF"), "dossier medical copie pdf")

    def test_ai_apps(self):
        for name in ("Otter.ai", "Fireflies.ai Meeting Notes", "ChatGPT", "Read AI", "Claude"):
            self.assertTrue(looks_like_ai_app(name), name)
        for name in ("Zoom", "Slack", "Dropbox", "Mailchimp", "Airtable"):
            self.assertFalse(looks_like_ai_app(name), name)


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

    def test_consent(self):
        legacy = {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": [
            "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]}}
        self.assertEqual(m365.analyse_consent_policy(legacy).severity, "high")
        self.assertEqual(m365.analyse_consent_policy({}).id, "m365-user-consent-none")

    def test_grants_skip_microsoft(self):
        sps = {"a": {"displayName": "Teams", "appOwnerOrganizationId": next(iter(m365.MICROSOFT_TENANTS))},
               "b": {"displayName": "Fathom", "appOwnerOrganizationId": "z"}}
        fs = m365.analyse_grants([{"clientId": "a", "scope": "Mail.Read"},
                                  {"clientId": "b", "consentType": "Principal", "scope": "Calendars.Read"}], sps)
        self.assertEqual([f.id for f in fs], ["m365-apps-ai"])
        self.assertEqual(fs[0].items[0]["granted for"], "1 person")


class Report(unittest.TestCase):
    def test_demo_report(self):
        results = demo.run()
        with tempfile.TemporaryDirectory() as d:
            paths = report.write(results, d)
            md, html, raw = (read(paths[k]) for k in ("report.md", "report.html", "findings.json"))
            data = json.loads(raw)
            self.assertIn("Fix first", md)
            self.assertIn("<!doctype html>", html)
            self.assertEqual(len(data), 2)
            self.assertEqual(oct(os.stat(paths["report.md"]).st_mode & 0o777), "0o600")
            for text in (md, html):
                self.assertNotIn("—", text)
                self.assertNotIn("–", text)

    def test_html_escapes(self):
        from airc.findings import Finding, Result
        r = Result(platform="Test")
        r.add(Finding(id="x", severity="low", title="t", why="w", fix="f", items=[{"name": "<script>x</script>"}]))
        self.assertNotIn("<script>x", report.to_html([r]))


if __name__ == "__main__":
    unittest.main()
