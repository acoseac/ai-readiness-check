# Changelog

## 0.2.0 (23 November 2026)

Tested by hand against a live Google Workspace and a Microsoft 365 test tenant, Conditional
Access included.

### Sign-in
- Browser sign-in with PKCE is now the default on both platforms. No device code to type.
- `--no-browser`: device code on Microsoft 365 (with a warning about device-code phishing), and
  paste-back on Google, for Cloud Shell or computers without a browser.
- The sign-in token stays in memory and is never saved. Microsoft 365 asks for four read
  permissions, down from five.
- Every request is checked against a short list of Microsoft and Google addresses, redirects
  included, and the token is never sent anywhere else.
- At the end of a run the tool prints how to remove the access it was given.

### New checks
- Public Microsoft 365 groups and Teams that anyone in the organisation can join and read
  (Viva Engage's own All Company groups are noted apart).
- Files shared with "Everyone except external users" or "Everyone" are recognised by the groups'
  fixed internal names, so translated tenants are covered.
- MFA: Conditional Access policies that cover only some people are reported; authentication
  strength counts as MFA; Microsoft's own template exclusions do not make a policy partial.
- Device code sign-in: whether Conditional Access blocks it for everyone.
- File names in Spanish and Arabic, AI meeting notes and transcripts, and `--keywords` for an
  organisation's own words.

### Fewer false alarms
- Apps whose access was revoked, and sharing links that have expired, are left out.
- The tool no longer lists its own sign-in app as a connected app.
- Google's own AI apps are reported for context, apart from outside AI apps.

### Report
- A summary line makes clear that names matching nothing are not an all-clear.
- Every exposed file links to itself, with its last-changed date.
- Advice on fixing things without breaking daily work, in the report and the checklist.

### Docs
- Setup guides with exact permissions and how to remove them, a Windows note, and Cloud Shell.
- A "related tools" section (ScubaGear, ScubaGoggles, Maester).
- The chatbot test is now a smoke test, pointing to Promptfoo, garak and PyRIT for red-teaming.

## 0.1.0 (23 November 2026)

First version: read-only Google Workspace and Microsoft 365 checks, plain-language report,
manual checklist, staff guidance template and pre-launch chatbot tests.
