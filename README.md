# AI readiness check

A free, read-only check for small humanitarian and civil-society organisations that are about to
switch on, or have already switched on, an AI assistant such as Microsoft 365 Copilot or Gemini.

AI assistants answer from everything a person is allowed to open. In most small organisations,
years of quick sharing mean that is more than anyone thinks: a beneficiary list open to anyone
with the link, salaries open to the whole organisation, a meeting-note bot connected to someone's
calendar. This check finds those things and explains, in plain words, what to fix first.

Early version (0.1). It works, it is small enough to read in an evening, and it needs feedback
from real organisations. Please open an issue with what was useful, wrong or missing.

## The rules it follows

- **Read-only.** It asks only for read permissions and sends only GET requests for data.
  It changes nothing in your tenant. (Signing in records your consent to those read permissions;
  the setup guides say how to remove it afterwards.)
- **Names, not contents.** It reads file names, sharing settings, account settings and connected
  apps. It never opens or downloads a file.
- **Runs on your computer, with your sign-in.** Nobody else gets credentials or admin access.
  Your IT person runs it and keeps the results.
- **Nothing leaves your machine.** The report is written to a local folder. No telemetry.
- **No dependencies.** Python 3.10 or newer and the standard library only, so you can read every
  line before you run it.

## Try it

```
git clone <this repository>
cd ai-readiness-check
python3 -m airc demo
```

`demo` builds a sample report for a made-up organisation, with no sign-in. Open the
`report.html` it prints.

Then, on your own tenant:

```
python3 -m airc google --client client.json     # Google Workspace, see docs/setup-google.md
python3 -m airc m365                            # Microsoft 365, see docs/setup-m365.md
```

## What it checks

| Area | Google Workspace | Microsoft 365 |
|---|---|---|
| Files shared with anyone with the link | yes | yes |
| Files open to the whole organisation | yes | yes |
| Files shared with people outside | from the audit log | yes |
| File names that suggest sensitive content (ID documents, beneficiaries, case notes, health, pay, donors, AI meeting notes and transcripts, passwords; English, French, German) | yes | yes |
| AI and meeting-note apps connected by staff | yes | yes |
| Other apps with access to mail, files or calendars | yes | yes |
| Whether staff can connect apps on their own | manual | yes |
| Outside sharing level | per shared drive (optional) | tenant-wide |
| 2-step verification / MFA | per account | enforcement policy |
| Copilot licences | n/a | yes |
| Gemini and Copilot settings | manual | manual |

Each finding is ranked "Fix first", "Fix soon", "Worth a look" or "For context", with why it
matters and what to do.

What the scripts cannot see is covered by:

- [docs/checklist.md](docs/checklist.md): the manual checks (assistant settings, MFA, site-wide
  access, guidance).
- [docs/staff-guidance-template.md](docs/staff-guidance-template.md): a one-page guide for staff.
- [docs/pre-launch-test.md](docs/pre-launch-test.md): ten harmless tests for teams building their
  own chatbot or agent.

## Suggested use

Half a day with the organisation's IT focal point: run the script together, read the report,
fix the "Fix first" items on the spot, then go through the checklist. The report lists names
from your organisation, so keep it private and delete it when you are done.

## Limits

This version sees what the signed-in admin can see, plus (on Google) the audit log for the last
180 days. It does not yet cover every personal OneDrive or every user's Drive. File names are a
hint, not proof: a sensitive file with a dull name will be missed, and some flagged files will
be harmless. The setup guides list the limits for each platform.

## Running the tests

```
python3 -m unittest discover -s tests
```

## Licence

Apache 2.0. See [LICENSE](LICENSE).
