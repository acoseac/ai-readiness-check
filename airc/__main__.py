"""Command line: python3 -m airc demo | google | m365"""

import argparse
import os
from datetime import datetime

from . import __version__, report


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m airc", description=(
        "Read-only AI readiness check for small organisations on Google Workspace or Microsoft 365. "
        "Nothing is changed, no file contents are read, and the report stays on this computer."))
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="build a sample report from made-up data, no sign-in")
    g = sub.add_parser("google", help="check a Google Workspace tenant")
    g.add_argument("--client", required=True, help="path to your OAuth client JSON (Desktop app), see docs/setup-google.md")
    g.add_argument("--days", type=int, default=180, help="how far back to read audit logs (default 180)")
    g.add_argument("--shared-drives", action="store_true",
                   help="also check shared drive settings (asks for the wider Drive read permission)")
    m = sub.add_parser("m365", help="check a Microsoft 365 tenant")
    m.add_argument("--tenant", default="organizations", help="tenant domain or id (default: the account's own)")
    m.add_argument("--client-id", default=None, help="your own app registration, see docs/setup-m365.md")
    m.add_argument("--max-sites", type=int, default=50)
    for p in (d, g, m):
        p.add_argument("--out", default=None, help="folder for the report (default: airc-report-<date>)")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        from . import demo
        results = demo.run()
    elif a.cmd == "google":
        from . import google_ws
        print("Google Workspace check (read-only)")
        results = [google_ws.run(a.client, days=a.days, shared_drives=a.shared_drives)]
    else:
        from . import m365
        print("Microsoft 365 check (read-only)")
        kw = {"client_id": a.client_id} if a.client_id else {}
        results = [m365.run(a.tenant, max_sites=a.max_sites, **kw)]

    out = a.out or f"airc-report-{datetime.now().strftime('%Y%m%d-%H%M')}"
    paths = report.write(results, out)
    for r in results:
        c = r.counts()
        print(f"\n{r.platform}: {c['high']} fix first, {c['medium']} fix soon, {c['low']} worth a look.")
        for e in r.errors:
            print(f"  did not run: {e}")
    print(f"\nReport: {os.path.abspath(paths['report.html'])}")
    print("It lists names from your organisation. Keep it private and delete it when done.")


if __name__ == "__main__":
    main()
