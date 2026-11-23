# Test data

Fake files for trying the check on a test tenant. Every name and number here is made up.

1. Upload the files in `sample-files/` to the test tenant (Google Drive or a SharePoint site).
2. Share them in different ways, so the report has something to find:
   - `DEMO Beneficiary list Q3.csv`: anyone with the link (expected: Fix first)
   - `DEMO Salaires 2026.csv`: everyone in the organisation with the link (expected: Fix soon)
   - `DEMO Case notes.txt`: share with an outside address you own (expected: Fix soon)
   - `DEMO Team lunch menu.txt`: anyone with the link (expected: Fix soon, not sensitive)
   - a new folder `DEMO Photos` with any file in it: anyone with the link (expected: Fix first,
     because folders open to anyone are checked whatever their name)
3. Run the check, compare the report with the expected results, then delete the files.

`DEMO Case notes.txt` also contains the canary string used in docs/pre-launch-test.md, so you
can reuse it to test a chatbot.

Run `python3 -m airc demo` to see a sample report with no sign-in at all.
