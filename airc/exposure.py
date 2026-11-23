"""Shared rules for files that are shared too widely, used by both platforms.

Each file is a dict: name, exposure ("anyone", "domain" or "external"), kind ("file" or
"folder"), plus optional owner, where and hints (filled in here from the name)."""

from .findings import Finding
from .patterns import hints as name_hints

WHY_ANYONE = ("Anyone who has the link can open these without signing in. Links get forwarded, "
              "pasted into chats and saved in browser histories, so they are the commonest way "
              "lists and case files leak.")
WHY_DOMAIN = ("Anyone in the organisation who gets the link can open these. Files that are "
              "findable by everyone, or shared with an 'Everyone' group, also turn up in search "
              "and in Copilot or Gemini answers for every colleague, even if nobody remembers "
              "sharing them.")
WHY_EXTERNAL = ("People outside the organisation can open these. If they use AI tools of their "
                "own, the content can end up there too.")

FIX_ANYONE = ("Open each file's sharing settings and change 'Anyone with the link' to named "
              "people or groups. If a link is needed for partners, add an expiry date. For "
              "folders, everything inside is exposed, so fix the folder first.")
FIX_DOMAIN = ("Limit these to the team that needs them. If you are about to switch on an AI "
              "assistant, fix sensitive ones before you do, and ask owners to review the rest.")
FIX_EXTERNAL = ("Check with the owner that each outside person still needs access, and remove "
                "those who do not.")


def _item(f):
    item = {"name": f.get("name", "(no name)") + (" [folder]" if f.get("kind") == "folder" else "")}
    if f.get("hints"):
        item["looks like"] = ", ".join(f["hints"])
    for k in ("how", "owner", "where", "seen", "link"):
        if f.get(k):
            item[k] = f[k]
    return item


def findings(files, prefix):
    """Group exposed files into findings. prefix keeps ids unique per platform."""
    for f in files:
        if "hints" not in f:
            f["hints"] = name_hints(f.get("name", ""))
    groups = {}
    for f in files:
        sens = bool(f["hints"])
        groups.setdefault((f["exposure"], sens), []).append(f)

    def sort(fs):  # folders first, then sensitive categories, then name
        return sorted(fs, key=lambda f: (f.get("kind") != "folder", f.get("name", "").lower()))

    out = []
    spec = [
        ("anyone", True, "high", "Sensitive-looking files open to anyone with the link", WHY_ANYONE, FIX_ANYONE),
        ("anyone", False, "medium", "Files open to anyone with the link", WHY_ANYONE, FIX_ANYONE),
        ("domain", True, "medium", "Sensitive-looking files open to the whole organisation", WHY_DOMAIN, FIX_DOMAIN),
        ("external", True, "medium", "Sensitive-looking files shared with people outside", WHY_EXTERNAL, FIX_EXTERNAL),
        ("domain", False, "low", "Other files open to the whole organisation", WHY_DOMAIN, FIX_DOMAIN),
        ("external", False, "low", "Other files shared with people outside", WHY_EXTERNAL, FIX_EXTERNAL),
    ]
    for exposure, sens, sev, title, why, fix in spec:
        fs = groups.get((exposure, sens))
        if fs:
            out.append(Finding(id=f"{prefix}-share-{exposure}-{'sensitive' if sens else 'other'}",
                               severity=sev, title=f"{title} ({len(fs)})", why=why, fix=fix,
                               items=[_item(f) for f in sort(fs)]))
    return out
