# Manual checklist

The scripts cover what can be read safely through the APIs. These checks need a person in the
admin console. Tick each one, or write down why it does not apply. Menu names change from time
to time; search the admin console for the setting if a path has moved.

## Everyone

- [ ] There is a short list of AI tools staff may use for work, and it says which accounts to use
      (work accounts, not personal ones).
- [ ] Staff have a one-page guide on what never goes into an AI tool (see staff-guidance-template.md).
- [ ] Someone is named to call if personal data was pasted into the wrong tool, and staff know it
      is fine to report it.
- [ ] Meeting bots and note-takers: decide whether they are allowed, and tell partners and
      participants when a meeting is recorded or transcribed.
- [ ] Admin accounts use 2-step verification with a passkey or security key, and are not used for
      daily mail.
- [ ] Before switching on an assistant, the "Fix first" items from the report are done.
- [ ] If you are building your own chatbot or agent: run docs/pre-launch-test.md first.

## Google Workspace

- [ ] Generative AI > Gemini app: on only for the groups that need it, and with the work account.
- [ ] Generative AI > Gemini app > Apps > Workspace apps: decide whether the Gemini app may use
      Drive, Gmail and other Workspace apps. It is on by default
      ([Google](https://knowledge.workspace.google.com/admin/generative-ai/gemini-app/turn-google-apps-in-gemini-on-or-off)).
- [ ] Generative AI > Gemini for Workspace (Gmail, Docs, Drive): decide on or off per group. Note
      that it answers from everything the person can open in Drive.
- [ ] Generative AI > NotebookLM: decide who may use it and with which data.
- [ ] Gemini conversation history: decide how long it is kept.
- [ ] Security > Access and data control > API controls > App access control: block or limit
      third-party apps nobody has reviewed, especially AI and meeting-note apps.
- [ ] Apps > Google Workspace > Drive and Docs > Sharing settings: link sharing off by default,
      sharing outside only to allowed domains, and a warning when people share outside.
- [ ] Data protection rules (if your edition has them): a rule for passport numbers, IBANs and
      similar identifiers.
- [ ] Security > Authentication > 2-step verification: enforced for everyone.

## Microsoft 365

- [ ] MFA for everyone: security defaults on, or Conditional Access requiring MFA (Entra admin
      centre > Protection).
- [ ] With Conditional Access (Entra ID P1 or Business Premium): device code sign-in blocked for
      everyone except accounts that really need it. Microsoft recommends this
      ([Microsoft](https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows)).
- [ ] After running this check: if you approved its permissions for the whole organisation,
      revoke them (see setup-m365.md, Afterwards).
- [ ] SharePoint sites and Teams: no site has "Everyone except external users" in its members or
      visitors unless it is meant for the whole organisation, and private material is not in
      public teams. This is the main reason Copilot finds things it should not. The report lists
      public groups and teams; sites where someone added "Everyone except external users" by hand
      need a look here.
- [ ] Microsoft 365 admin centre > Copilot > Settings: decide whether Copilot Chat may search the
      web, and which agents staff may use or build.
- [ ] Copilot Studio and agent sharing: who may create agents and share them with others.
- [ ] If you have Copilot licences: consider Restricted Content Discovery for sites that hold case,
      HR or finance files, so Copilot does not search them.
- [ ] Sensitivity labels (Business Premium and up): a "Confidential: protection data" label for case
      files, at least applied by hand.
- [ ] Teams meeting recordings and transcripts: who can start them and how long they are kept.
- [ ] Entra admin centre > Users, filter by Guest: remove guests who no longer work with you.

## Fixing it without breaking daily work

The report ends with the same advice.

- Start with "Fix first": sensitive-looking names, and folders open to anyone with the link.
  Old brochures and public reports can wait.
- Before you remove a link that partners may use (grant portals, donor sheets, intake forms),
  tell the owner. Then switch it to named people rather than deleting it. SharePoint and
  OneDrive can make Anyone links expire (SharePoint admin centre > Policies > Sharing;
  [Microsoft](https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off)).
  Google Drive can put an end date on a named person's access
  ([Google](https://support.google.com/drive/answer/2494893)).
- The "changed" date in the report shows when a file was last edited, not when it was last
  opened. A reference sheet nobody edits may still be opened through its link every week, so
  ask the owner before tightening anything you are not sure about.
- Change a few at a time, and keep a list of what you changed (file, old setting, new setting,
  date) so you can undo it if something breaks.
- On Microsoft 365 with Copilot licences, Restricted Content Discovery keeps a site out of
  Copilot and organisation-wide search while you clean up. It does not change who can open the
  files (SharePoint admin centre > Sites > Active sites > the site > Settings;
  [Microsoft](https://learn.microsoft.com/en-us/sharepoint/restricted-content-discovery)).
