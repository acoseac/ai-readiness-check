"""pilot-stats.json (--anon-summary): counts and yes/no answers that an organisation could choose
to share with a pilot, for example to compare results across organisations.

It holds no file, user, app, group or domain names, no email addresses, ids, links or tenant
names, and no date more exact than the month of the run. Every value comes from the report
next to it, so the organisation can check it there. Nothing is sent anywhere."""

from . import __version__
from .access import can_act

FILE_NAME = "pilot-stats.json"

ABOUT = ("Counts and yes/no answers from this check, with no names, email addresses, ids, links or exact "
         "dates. It was written to this folder only and has not been sent anywhere. Sharing it is your choice.")

# Shown in the terminal and in the report when the file is written.
NOTE = ("pilot-stats.json holds only counts and yes/no answers (no file, user, app, group or domain names, "
        "no email addresses, ids or links, and only the month of the run). It has not been sent anywhere; "
        "sharing it, for example with a pilot, is your choice.")

LABELS = {"high": "fix_first", "medium": "fix_soon", "low": "worth_a_look", "info": "for_context"}


def bucket(n):
    """Active accounts as a range, so the exact size of the organisation is not shared."""
    if n is None:
        return None
    if n <= 10:
        return "1-10" if n > 0 else "0"
    if n <= 50:
        return "11-50"
    if n <= 200:
        return "51-200"
    return "201+"


def _items(result, finding_id):
    for f in result.findings:
        if f.id == finding_id:
            return f.items
    return []


def _has(result, *ids):
    return any(f.id in ids for f in result.findings)


def platform_stats(r):
    """The shareable counts for one Result. A value is null when the check behind it did not run."""
    prefix = "gws" if r.platform == "Google Workspace" else "m365"
    ran = set(r.checked)

    def count(key, finding_id):
        return len(_items(r, finding_id)) if key in ran else None

    def files(exposure, *groups):
        if "files" not in ran:
            return None
        return {("sensitive_looking" if g == "sensitive" else "folders" if g == "folder" else g):
                len(_items(r, f"{prefix}-share-{exposure}-{g}")) for g in groups}

    ai = _items(r, f"{prefix}-apps-ai")
    counts = r.counts()
    out = {
        "platform": r.platform,
        "active_accounts": bucket(r.active_accounts),
        "findings": {LABELS[s]: counts[s] for s in LABELS},
        "checks_not_run": len(r.errors),
        "open_to_anyone": files("anyone", "sensitive", "folder", "other"),
        "open_to_whole_organisation": files("domain", "sensitive", "other"),
        "connected_ai_apps": len(ai) if "apps" in ran else None,
        "ai_apps_that_can_send_or_change": sum(1 for i in ai if can_act(i.get("access"))) if "apps" in ran else None,
    }
    if prefix == "gws":
        # Google: every active account is enrolled in 2-step verification.
        out["mfa_covers_everyone"] = (not _has(r, "gws-admin-2sv", "gws-user-2sv")) if "accounts" in ran else None
        out["admins_without_2sv"] = count("accounts", "gws-admin-2sv")
    else:
        # Microsoft 365: security defaults on, or a Conditional Access policy asks everyone for MFA.
        mfa = None
        if _has(r, "m365-mfa-security-defaults", "m365-mfa-ca"):
            mfa = True
        elif _has(r, "m365-mfa-ca-partial", "m365-mfa-off"):
            mfa = False
        out["mfa_covers_everyone"] = mfa
        # The other MFA findings are only made when security defaults are off.
        out["security_defaults_on"] = (True if _has(r, "m365-mfa-security-defaults") else
                                       False if _has(r, "m365-mfa-ca", "m365-mfa-ca-partial", "m365-mfa-off")
                                       else None)
        out["device_code_blocked"] = (True if _has(r, "m365-device-code-blocked") else
                                      False if _has(r, "m365-device-code-open") else None)
        out["public_groups"] = count("groups", "m365-public-groups")
    return out


def stats(results):
    started = min((r.started for r in results), default="")
    return {
        "about": ABOUT,
        "tool": "ai-readiness-check",
        "version": __version__,
        "run_month": started[:7] or None,
        "platforms": [platform_stats(r) for r in results],
    }
