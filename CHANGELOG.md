# Changelog

## Unreleased

- Connected apps (both platforms): each app's access now says whether it is read-only or can
  also send or change, for example "mail (can send), files (read-only)", from each platform's
  permission reference. Apps that can send or change are listed first, the AI apps title counts
  them, and the advice explains why they matter more (prompt injection). Severities are
  unchanged. Newly counted: Mail.Send.Shared, SMTP.Send, POP.AccessAsUser.All, Sites.Manage.All,
  Notes.ReadWrite.All, Calendars.ReadWrite.Shared, ChatMessage.Send, ChannelMessage.Send and
  OnlineMeetings.ReadWrite on Microsoft 365; gmail.send, gmail.compose, gmail.insert,
  calendar.events.owned and calendar.events.owned.readonly on Google.
- AI app names: Granola, Glean, Fyxer, Tactiq, Sembly, Supernormal, Krisp, Avoma, DeepSeek and
  Grok, plus the automation platforms Zapier, Make (make.com, Integromat) and n8n, which often run
  AI agents. Cursor, Dust, Gamma and Lindy count only as an app's whole name, since they are
  also ordinary words. The findings are now called "AI, meeting-note and automation apps".
- `--anon-summary` on `google`, `m365` and `demo` also writes `pilot-stats.json`: only counts and
  yes/no answers an organisation could choose to share with a pilot, with no names, addresses,
  ids, links or dates beyond the month. It is never sent anywhere; the report and the terminal
  say so.
- Microsoft 365: the run counts enabled member accounts (same read-only query as the guest
  count) and states both in what the run could see.
- Demo: shows an automation app that can send mail and change files, a read-only meeting-note
  app, and the Microsoft 365 MFA result.
- Gemini note and checklist: Gmail's AI Overview thread summaries and Help me write
  (non-personalised) are rolling out to all Workspace editions from 10 November 2026, on by
  default, with where an admin can turn them off and which editions have that switch.
- Connected apps (Google): the coverage note, the AI apps advice and the setup guide now say
  that an app an admin blocked for the whole organisation may still be listed, since that block
  is not logged as a revoke.
- Viva Engage groups (Microsoft 365): still matched by English name; a comment and a test record
  that a translated or renamed All Company group is reported with the public groups, and why
  there is no language-independent match.
- Sample report screenshot regenerated from the 0.2.0 demo.

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
