"""Shared rules for files that are shared too widely, used by both platforms.

Each file is a dict: name, exposure ("anyone", "domain" or "external"), kind ("file" or
"folder"), plus optional owner, where, modified (YYYY-MM-DD) and hints (filled in here from
the name)."""

from .findings import Finding
from .patterns import hints as name_hints

WHY_ANYONE = ("Anyone who has the link can open these without signing in. Links get forwarded, "
              "pasted into chats and saved in browser histories, so they are the commonest way "
              "lists and case files leak.")
WHY_FOLDER = ("Anyone who has the link can open these folders and everything in them, without "
              "signing in. This check does not look inside folders, so whatever their names, treat "
              "them as sensitive until someone has looked.")
WHY_DOMAIN = ("Anyone in the organisation who gets the link can open these. Files that are "
              "findable by everyone, or shared with an 'Everyone' group, also turn up in search "
              "and in Copilot or Gemini answers for every colleague, even if nobody remembers "
              "sharing them.")
WHY_EXTERNAL = ("People outside the organisation can open these. If they use AI tools of their "
                "own, the content can end up there too.")

GOOGLE_SHARING = "https://support.google.com/drive/answer/2494893"
M365_SHARING = "https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off"

# What to do differs by platform: SharePoint can make Anyone links expire, while Google Drive
# puts end dates on a named person's access, not on 'Anyone with the link'.
FIXES = {
    "gws": {
        "anyone": ("Tell the owner first: partners may use the link. Then open Share and change General "
                   "access from 'Anyone with the link' to 'Restricted', and add the people or groups who "
                   "need it. Partners can be added by name, with an end date on their access if needed. "
                   "For folders, fix the folder first: everything inside is open too."),
        "domain": ("Change General access to 'Restricted' and share with the team or group that needs "
                   "these. Ask owners before changing files they use every day, and fix sensitive ones "
                   "before you switch on an AI assistant."),
    },
    "m365": {
        "anyone": ("Tell the owner first: partners may use the link. Then open the item's sharing "
                   "settings (Manage access) and replace the Anyone link with one for specific people. "
                   "If partners need a link, use one that expires. For folders, fix the folder first: "
                   "everything inside is open too."),
        "domain": ("Remove 'People in your organisation' links and 'Everyone except external users' from "
                   "these, and give the team that needs them access instead. Ask owners before changing "
                   "files they use every day, and fix sensitive ones before you switch on Copilot."),
    },
}
FIX_EXTERNAL = ("Check with the owner that each outside person still needs access, and remove "
                "those who do not.")
SOURCES = {"gws": [GOOGLE_SHARING], "m365": [M365_SHARING]}


def _item(f):
    item = {"name": f.get("name", "(no name)") + (" [folder]" if f.get("kind") == "folder" else "")}
    if f.get("hints"):
        item["looks like"] = ", ".join(f["hints"])
    if f.get("modified"):
        item["changed"] = f["modified"]
    for k in ("how", "owner", "where", "seen", "link"):
        if f.get(k):
            item[k] = f[k]
    return item


def prepare(files, extra=None):
    """Fill in name hints. extra: a matcher from patterns.compile_terms (--keywords)."""
    for f in files:
        if "hints" not in f:
            f["hints"] = name_hints(f.get("name", ""), extra)
    return files


def _sort(fs):
    """Folders first, then the most recently changed, then by name."""
    fs = sorted(fs, key=lambda f: f.get("name", "").lower())
    fs = sorted(fs, key=lambda f: f.get("modified") or "", reverse=True)
    return sorted(fs, key=lambda f: f.get("kind") != "folder")


def findings(files, prefix, extra=None):
    """Group exposed files into findings. prefix ("gws" or "m365") keeps ids unique per
    platform and picks that platform's advice."""
    prepare(files, extra)
    fixes = FIXES.get(prefix, FIXES["m365"])
    groups = {}
    for f in files:
        if f["hints"]:
            group = "sensitive"
        elif f["exposure"] == "anyone" and f.get("kind") == "folder":
            group = "folder"
        else:
            group = "other"
        groups.setdefault((f["exposure"], group), []).append(f)

    spec = [
        ("anyone", "sensitive", "high", "Sensitive-looking files open to anyone with the link", WHY_ANYONE),
        ("anyone", "folder", "high", "Folders open to anyone with the link", WHY_FOLDER),
        ("anyone", "other", "medium", "Files open to anyone with the link", WHY_ANYONE),
        ("domain", "sensitive", "medium", "Sensitive-looking files open to the whole organisation", WHY_DOMAIN),
        ("external", "sensitive", "medium", "Sensitive-looking files shared with people outside", WHY_EXTERNAL),
        ("domain", "other", "low", "Other files open to the whole organisation", WHY_DOMAIN),
        ("external", "other", "low", "Other files shared with people outside", WHY_EXTERNAL),
    ]
    out = []
    for exposure, group, sev, title, why in spec:
        fs = groups.get((exposure, group))
        if fs:
            out.append(Finding(id=f"{prefix}-share-{exposure}-{group}", severity=sev,
                               title=f"{title} ({len(fs)})", why=why,
                               fix=fixes.get(exposure, FIX_EXTERNAL),
                               items=[_item(f) for f in _sort(fs)],
                               sources=list(SOURCES.get(prefix, [])) if exposure != "external" else []))
    return out


def summary(files, extra=None):
    """One line that is always shown under the counts, so that 'nothing matched' never reads as
    an all-clear."""
    prepare(files, extra)
    n = {e: sum(1 for f in files if f["exposure"] == e) for e in ("anyone", "domain", "external")}
    named = sum(1 for f in files if f["hints"])
    caveat = ("A name that matches nothing is not an all-clear: a file called 'Export final v3' is not "
              "flagged as sensitive, and only what this account could see was checked (see what this run could and "
              "could not see).")
    if not files:
        return "No files shared by link, organisation-wide or with outside people were found. " + caveat
    return (f"{n['anyone']} items open to anyone with the link, {n['domain']} to the whole organisation and "
            f"{n['external']} shared with people outside. {named} of them have names that matched the word "
            f"list. " + caveat)
