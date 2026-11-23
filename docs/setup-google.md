# Setting up the Google Workspace check

About 10 minutes, once. You need a super admin account.

The check signs in with an OAuth client that lives in your own Google Cloud project, so no
outside company is involved and Google never shows your data to anyone but you.

## 1. Create the OAuth client

1. Go to https://console.cloud.google.com and create a project, for example "AI readiness check".
2. APIs and services > Library: enable **Admin SDK API** and **Google Drive API**.
3. Google Auth Platform (or "OAuth consent screen"): choose **Internal**, give it a name and your
   email. Internal means only people in your organisation can use it, and Google does not need to
   review it.
4. Clients > Create client > Application type **Desktop app** > Create, then **Download JSON**.
   Save it next to the tool, for example as `client.json`. Treat it as private.

## 2. Run the check

```
python3 -m airc google --client client.json
```

A browser window opens. Sign in as a super admin and accept the read-only permissions:

| Permission | Why |
|---|---|
| See your email address | to label the report |
| See information about your Google Drive files (metadata only) | to find files shared by link; contents are never read |
| View users on your domain | to count accounts and check 2-step verification |
| View audit reports for your domain | to see sharing changes and connected apps across everyone |

The report is written to a new `airc-report-<date>` folder.

## 3. Afterwards

- Remove the tool's access: https://myaccount.google.com/permissions, find your client, Remove access.
- Delete the OAuth client or the whole project in Google Cloud if you will not run it again.
- Delete the report folder once you have acted on it.

## Limits in this version

- Drive is checked from two angles: files the signed-in admin can open, and the Drive audit log
  for the last 180 days (all users). A file shared by link years ago by someone else, and never
  shared with the admin, is not seen. Full coverage needs a service account with domain-wide
  delegation, which is planned for a later version as an opt-in.
- Audit logs need a Workspace edition that includes them. If yours does not, those checks are
  listed under "Checks that did not run".
- Most Gemini settings cannot be read by any read-only tool. See docs/checklist.md.
