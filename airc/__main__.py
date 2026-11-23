"""Command line: python3 -m airc demo | google | m365"""

import argparse
import os
from datetime import datetime

from . import __version__, report


def build_parser():
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
    g.add_argument("--no-browser", action="store_true",
                   help="for a computer with no browser (such as Cloud Shell): print the sign-in address, "
                        "then paste back the address the browser ends on")
    m = sub.add_parser("m365", help="check a Microsoft 365 tenant")
    m.add_argument("--tenant", default="organizations", help="tenant domain or id (default: the account's own)")
    m.add_argument("--client-id", default=None, help="your own app registration, see docs/setup-m365.md")
    m.add_argument("--max-sites", type=int, default=50)
    m.add_argument("--no-browser", action="store_true",
                   help="sign in with a device code instead of a browser on this computer "
                        "(only enter a code for a sign-in you started yourself)")
    for p in (g, m):
        p.add_argument("--keywords", metavar="FILE", default=None,
                       help="a text file with your own words to look for in file names, one per line "
                            "(for example project or programme names)")
    for p in (d, g, m):
        p.add_argument("--out", default=None, help="folder for the report (default: airc-report-<date>)")
    return ap


def main(argv=None):
    a = build_parser().parse_args(argv)
    keywords = None
    if getattr(a, "keywords", None):
        from .patterns import compile_terms, read_terms
        try:
            keywords = compile_terms(read_terms(a.keywords))
        except OSError as e:
            raise SystemExit(f"Could not read the keywords file: {e}") from None
        if keywords is None:
            raise SystemExit("The keywords file has no words in it (one per line; lines starting with # are skipped).")

    afterwards = ""
    if a.cmd == "demo":
        from . import demo
        results = demo.run()
    elif a.cmd == "google":
        from . import google_ws
        print("Google Workspace check (read-only)")
        results = [google_ws.run(a.client, days=a.days, shared_drives=a.shared_drives,
                                 no_browser=a.no_browser, keywords=keywords)]
        afterwards = google_ws.AFTERWARDS
    else:
        from . import m365
        print("Microsoft 365 check (read-only)")
        kw = {"client_id": a.client_id} if a.client_id else {}
        results = [m365.run(a.tenant, max_sites=a.max_sites, no_browser=a.no_browser, keywords=keywords, **kw)]
        afterwards = m365.AFTERWARDS

    out = a.out or f"airc-report-{datetime.now().strftime('%Y%m%d-%H%M')}"
    paths = report.write(results, out)
    for r in results:
        c = r.counts()
        print(f"\n{r.platform}: {c['high']} fix first, {c['medium']} fix soon, {c['low']} worth a look.")
        for e in r.errors:
            print(f"  did not run: {e}")
    print(f"\nReport: {os.path.abspath(paths['report.html'])}")
    print("It lists names from your organisation. Keep it private and delete it when done.")
    if afterwards:
        print("\n" + afterwards)


if __name__ == "__main__":
    main()
