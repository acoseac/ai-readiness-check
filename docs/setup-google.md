# Setting up the Google Workspace check

About 10 minutes, once. You need a super admin account.

The check signs in with an OAuth client that lives in your own Google Cloud project, so no
outside company is involved and Google never shows your data to anyone but you.

## 1. Create the OAuth client

1. Create a project, for example "AI readiness check": https://console.cloud.google.com/projectcreate
   Google may insist on a billing account. Pick any you have: the two APIs this tool uses are
   free, so nothing is charged.
2. Enable the two APIs in one step (pick the new project if asked):
   https://console.cloud.google.com/flows/enableapi?apiid=admin.googleapis.com,drive.googleapis.com
3. Google Auth Platform (or "OAuth consent screen") > Get started: give it a name and your
   email, choose **Internal**, and accept Google's API Services User Data Policy at the end.
   Internal means only people in your organisation can use it, and Google does not need to
   review it.
4. Clients > Create client > Application type **Desktop app** > Create, then **Download JSON**.
   Save it somewhere private, for example `~/.config/airc/client.json`, not inside a folder you
   share or sync. Google shows the secret only once; if you lose the file, delete the client and
   make a new one.
   If a password manager pops up over the form while you type the client's name, keep the
   default name instead.

## 2. Run the check

```
python3 -m airc google --client client.json
```

A browser window opens. If it opens in the wrong browser or profile, copy the address the tool
prints into the browser where your admin account is signed in. Sign in as a super admin and
accept the read-only permissions. Google enforces them: the token cannot change anything,
whatever the code does, and the tool sends it only to Google's addresses.

| Permission | Why |
|---|---|
| See your email address | to label the report |
| See information about your Google Drive files (metadata only) | to find files shared by link; contents are never read |
| View users on your domain | to count accounts and check 2-step verification |
| View audit reports for your domain | to see sharing changes and connected apps across everyone |

The report is written to a new `airc-report-<date>` folder.

Options:

- `--no-browser` for a computer with no browser, such as Cloud Shell (below). The tool prints
  the sign-in address; open it in any browser and sign in. Google then sends the browser to an
  address starting with `http://127.0.0.1:`, which fails to load ("site cannot be reached").
  That is expected. Copy the whole address from the address bar and paste it into the terminal.
  It is not shown as you paste. The tool checks that it belongs to this sign-in.
- `--keywords words.txt` adds your own words to the file-name check: a text file with one term
  per line, such as programme or project names. Lines starting with `#` are skipped. Terms are
  matched at the start of a word, ignoring case and accents; terms of four letters or fewer must
  match a whole word, so `WASH` does not match `Washington`. A file keeps the words out of your
  shell history.
- `--days 90` reads less of the audit log (default 180 days).
- `--shared-drives`, see the limits below.

On Windows, type `py` instead of `python3`.

## Or run it in Google Cloud Shell

Cloud Shell is a terminal in the browser with Python and git already installed
([Google](https://docs.cloud.google.com/shell/docs/how-cloud-shell-works)). It saves installing
Python, but you still need the OAuth client from step 1.

1. Open https://shell.cloud.google.com signed in as the super admin.
2. More > Upload, and upload your `client.json`
   ([Google](https://docs.cloud.google.com/shell/docs/uploading-and-downloading-files)).
3. Run:
   ```
   git clone https://github.com/acoseac/ai-readiness-check.git
   cd ai-readiness-check
   python3 -m airc google --client ~/client.json --no-browser
   ```
4. Download the report: `cloudshell download airc-report-*/report.html`
5. Delete the report and the client file from Cloud Shell: `rm -r airc-report-* ~/client.json`

On this route the report is written to your Cloud Shell home directory, on Google's servers,
until you delete it. "Nothing leaves your machine" then means: nothing leaves your Google
account. If Cloud Shell is not available in your organisation (admins can turn it off), run the
check on your own computer.

## 3. Afterwards

The tool prints these steps at the end of each run.

- Remove the tool's access: https://myaccount.google.com/permissions, find your client, Remove access.
- Delete the OAuth client or the whole project in Google Cloud if you will not run it again.
- Delete the report folder once you have acted on it.

## Limits in this version

- Drive is checked from two angles: files the signed-in admin can open, and the Drive audit log
  for the last 180 days (all users). A file shared by link years ago by someone else, and never
  shared with the admin, is not seen. Full coverage needs a service account with domain-wide
  delegation, which is planned for a later version as an opt-in.
- Connected apps come from the token audit log: apps staff authorised in the last 180 days,
  leaving out apps each person's access was revoked for afterwards. Apps authorised before then
  are not listed. An app an admin blocked for the whole organisation in App access control may
  still be listed: Google records that block in the admin audit log, not as a revoke in the token
  log ([token events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token),
  [admin events](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/admin-security-settings)).
- "The domain administrators have disabled Drive apps" means your Drive settings block apps from
  the Drive API (Apps > Google Workspace > Drive and Docs > Features and applications > Drive
  SDK). That is a safe setting and there is no need to change it: the audit log still shows
  sharing changes. Only the admin-view file check is skipped.
- Shared drive settings need the wider Drive read permission (which could read file contents),
  so they are off by default. Add `--shared-drives` if you want them.
- Audit logs need a Workspace edition that includes them. If yours does not, those checks are
  listed under "Checks that did not run".
- This check does not read Gemini settings. Check them by hand with docs/checklist.md.
