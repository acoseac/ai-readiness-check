# Setting up the Microsoft 365 check

No setup is needed for a first run. You need a **Global Administrator** the first time (to
approve the read permissions) and a **Global Reader** account after that.

## Run the check

```
python3 -m airc m365
```

The tool prints a short code. Open https://microsoft.com/devicelogin, enter the code and sign in.
The first time, Microsoft asks an admin to approve these read permissions for "Microsoft Graph
Command Line Tools", Microsoft's own public sign-in app for Graph tools:

| Permission | Why |
|---|---|
| Read all users' full profiles | to count guests |
| Read directory data | apps staff have connected, licences |
| Read your organisation's policies | the app consent setting, security defaults and Conditional Access (MFA) |
| Read items in all site collections | to find files shared widely (names only) |
| Read SharePoint tenant settings | the outside sharing level |

Options: `--tenant contoso.onmicrosoft.com` to choose the tenant, `--max-sites 200` to look at
more sites (default 50).

## If you prefer your own app registration

Some organisations block the Graph Command Line Tools app. Then:

1. Entra admin centre > App registrations > New registration, "Accounts in this organisational
   directory only", no redirect URI.
2. Authentication > Allow public client flows: **Yes**.
3. API permissions > Microsoft Graph > Delegated: User.Read.All, Directory.Read.All,
   Policy.Read.All, Sites.Read.All, SharePointTenantSettings.Read.All > Grant admin consent.
4. Run `python3 -m airc m365 --tenant <your tenant> --client-id <application id>`.

## Afterwards

- Approving the permissions leaves a consent record in your tenant. To remove it: Entra admin
  centre > Enterprise applications > Microsoft Graph Command Line Tools (or your own app) >
  Permissions, or delete the enterprise application.
- Delete the report folder once you have acted on it.

## Limits in this version

- SharePoint is checked for the sites the signed-in account can see, and only item-level sharing.
  Site-wide access (for example "Everyone except external users" added to a site's members, or a
  public team) is in docs/checklist.md, and is the most common reason Copilot finds things it
  should not.
- Personal OneDrives are not covered yet.
- MFA is judged from security defaults and Conditional Access policies, not from each person's
  registration. Per-user MFA settings are not read.
