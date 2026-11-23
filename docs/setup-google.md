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
accept the read-only permissions:

| Permission | Why |
|---|---|
| See your email address | to label the report |
| See information about your Google Drive files (metadata only) | to find files shared by link; contents are never read |
| View users on your domain | to count accounts and check 2-step verification |
| View audit reports for your domain | to see sharing changes and connected apps across everyone |

The report is written to a new `airc-report-<date>` folder.

On Windows, type `py` instead of `python3`.

## 3. Afterwards

- Remove the tool's access: https://myaccount.google.com/permissions, find your client, Remove access.
- Delete the OAuth client or the whole project in Google Cloud if you will not run it again.
- Delete the report folder once you have acted on it.

## Limits in this version

- Drive is checked from two angles: files the signed-in admin can open, and the Drive audit log
  for the last 180 days (all users). A file shared by link years ago by someone else, and never
  shared with the admin, is not seen. Full coverage needs a service account with domain-wide
  delegation, which is planned for a later version as an opt-in.
- "The domain administrators have disabled Drive apps" means your Drive settings block apps from
  the Drive API (Apps > Google Workspace > Drive and Docs > Features and applications > Drive
  SDK). That is a safe setting and there is no need to change it: the audit log still shows
  sharing changes. Only the admin-view file check is skipped.
- Shared drive settings need the wider Drive read permission (which could read file contents),
  so they are off by default. Add `--shared-drives` if you want them.
- Audit logs need a Workspace edition that includes them. If yours does not, those checks are
  listed under "Checks that did not run".
- Most Gemini settings cannot be read by any read-only tool. See docs/checklist.md.
