# Setting up the Microsoft 365 check

No setup is needed for a first run.

## Which account to use

- **To approve the permissions** (the first time) you need an admin who can approve app
  permissions: a Global Administrator, or, per Microsoft, a Privileged Role Administrator, Cloud
  Application Administrator or Application Administrator
  ([Microsoft](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)).
- **To read the settings** the account needs Global Reader or Global Administrator.
- **To see files**, the account must be a member or owner of the SharePoint sites that hold
  case, HR and finance files. The check uses delegated permissions, so it can open only what the
  signed-in account can open
  ([Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)),
  and admin roles do not give automatic access to site content
  ([Microsoft](https://learn.microsoft.com/en-us/sharepoint/sharepoint-admin-role)). Sites the
  account does not belong to are not checked: treat them as unchecked, not as clean.

## Run the check

```
python3 -m airc m365
```

A browser window opens at Microsoft's sign-in page. Sign in there; the browser then hands the
answer back to the tool on your own computer (to `http://localhost`), and the terminal carries
on. If the browser shows a Microsoft error instead (for example AADSTS50011) and the terminal
just waits, press Ctrl+C and use one of the options below.

The first time, Microsoft asks you to approve these read permissions for "Microsoft Graph
Command Line Tools", Microsoft's own public sign-in app for Graph tools.

**Leave "Consent on behalf of your organization" unticked.** Admins can approve permissions for
themselves or for the whole organisation
([Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview)).
Approving for the whole organisation lets every user in the tenant use the app with these
permissions, unless restricted
([Microsoft](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)).
Graph Command Line Tools is a public app that anyone in the tenant can sign in to, so an
organisation-wide approval also means a phished colleague would see no permissions prompt to
make them stop and think. Unticked, the approval covers only your account.

| Permission | Why |
|---|---|
| Read directory data (Directory.Read.All) | apps staff have connected, licences, the guest count |
| Read your organisation's policies (Policy.Read.All) | the app consent setting, security defaults and Conditional Access (MFA, device code sign-in) |
| Read items in all site collections (Sites.Read.All) | to list sites and files and their sharing. This permission could read file contents; the code asks only for names, dates and sharing. Microsoft offers no narrower permission for listing other people's sharing |
| Read SharePoint tenant settings (SharePointTenantSettings.Read.All) | the outside sharing level |

Microsoft enforces these permissions: the token cannot change anything, whatever the code does.
The sign-in token stays in memory on your computer for the run and is never saved to disk, and
the tool sends it only to Microsoft's sign-in and Graph addresses.

Options:

- `--tenant contoso.onmicrosoft.com` to choose the tenant.
- `--max-sites 200` to look at more sites (default 50).
- `--keywords words.txt` to add your own words to the file-name check: a text file with one
  term per line, such as programme or project names. Lines starting with `#` are skipped. Terms
  are matched at the start of a word, ignoring case and accents, so `donor` also finds `donors`.
  A file keeps the words out of your shell history.
- `--no-browser` signs in with a device code instead, for a computer without a browser. The
  tool prints a code and an address (microsoft.com/devicelogin). **Only enter a code for a
  sign-in you started yourself, just now.** Attackers send people codes like this to steal
  their sign-in. Microsoft recommends blocking device code sign-in wherever possible
  ([Microsoft](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows)),
  and some tenants have a Microsoft-managed policy that does
  ([Microsoft](https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies)),
  so this option may not work in yours. That is why the browser is the default.

On Windows, type `py` instead of `python3`.

## If you prefer your own app registration

Some organisations block the Graph Command Line Tools app, or prefer an app they can delete
afterwards. Then:

1. Entra admin centre > App registrations > New registration, "Accounts in this organisational
   directory only".
2. Authentication > Add a platform > **Mobile and desktop applications**, custom redirect URI
   `http://localhost`. (Microsoft ignores the port for localhost addresses, so the tool can use
   any free one;
   [Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url).)
3. Only if you will use `--no-browser`: Authentication > Allow public client flows: **Yes**.
4. API permissions > Microsoft Graph > Delegated: Directory.Read.All, Policy.Read.All,
   Sites.Read.All, SharePointTenantSettings.Read.All. Grant admin consent here only if you
   want the app usable by others; otherwise approve for yourself at the first sign-in.
5. Run `python3 -m airc m365 --tenant <your tenant> --client-id <application id>`.

## Afterwards

The tool prints these steps at the end of each run.

- **If you ticked "Consent on behalf of your organization":** Entra admin centre > Enterprise
  apps > Microsoft Graph Command Line Tools > Permissions > Admin consent tab. For each
  permission this check added, choose **...** > **Revoke permission**
  ([Microsoft](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions)).
  If your IT team uses Microsoft Graph PowerShell, keep the permissions they rely on.
- **If you left it unticked:** the approval covers only your account. Microsoft's portal cannot
  remove that kind of approval (the User consent tab is read-only there); Microsoft documents
  removing it with PowerShell or Graph on the same page. Deleting the enterprise application
  also removes it, but that removes the app for anyone else in the organisation who uses
  Microsoft Graph PowerShell too.
- **With your own app registration:** delete the app registration.
- Delete the report folder once you have acted on it.

## Limits in this version

- SharePoint is checked for the sites the signed-in account belongs to (see "Which account to
  use"), and only item-level sharing. Where Microsoft marks no item in a library as shared, the
  first 200 files are checked. The check stops after 3,000 sharing checks. The report states
  these numbers for each run.
- Microsoft returns all sharing details only to an item's owners; for other people it shows
  only the sharing that applies to them
  ([Microsoft](https://learn.microsoft.com/en-us/graph/api/driveitem-list-permissions)). Anyone
  links created by others on a site where the account is a member but not an owner may be
  missed.
- Site-wide access (for example "Everyone except external users" added to a site's members, or
  a public team) is in docs/checklist.md, and is the most common reason Copilot finds things it
  should not.
- Personal OneDrives are not covered yet.
- Microsoft's Data access governance reports (SharePoint admin centre > Reports > Data access
  governance, part of SharePoint Advanced Management) cover every SharePoint and OneDrive site
  ([Microsoft](https://learn.microsoft.com/en-us/sharepoint/data-access-governance-reports)).
  If your tenant has them, run them as well.
- MFA is judged from security defaults and Conditional Access policies, not from each person's
  registration. Per-user MFA settings are not read. Conditional Access needs Entra ID P1
  (included in Business Premium); without it the device code finding is skipped.
