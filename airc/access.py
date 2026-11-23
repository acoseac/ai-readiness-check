"""What a connected app's granted permissions let it do: only read, or also send or change.

Each platform keeps a table {area: {scope: abilities}}, checked against the platform's official
permission reference (see the comments in m365.py and google_ws.py). An app's access in an area
is the widest of the abilities its scopes give there."""

READ, SEND, CHANGE = "read", "send", "change"
R = frozenset({READ})
S = frozenset({SEND})
C = frozenset({CHANGE})
RC = frozenset({READ, CHANGE})
SC = frozenset({SEND, CHANGE})
RSC = frozenset({READ, SEND, CHANGE})

READ_ONLY = "read-only"


def _label(abilities):
    if SEND in abilities and CHANGE in abilities:
        return "can send and change"
    if SEND in abilities:
        return "can send"
    if CHANGE in abilities:
        return "can change"
    return READ_ONLY


def describe(scopes, table):
    """Return (text, acts) for a set of granted scopes. text is, for example,
    "mail (can send), files (read-only)"; acts is True when any area can send or change.
    Scopes are compared without regard to case."""
    granted = {s.lower() for s in scopes if s}
    parts, acts = [], False
    for area, levels in table.items():
        abilities = set()
        for scope, ab in levels.items():
            if scope.lower() in granted:
                abilities |= ab
        if abilities:
            parts.append(f"{area} ({_label(abilities)})")
            acts = acts or bool(abilities & {SEND, CHANGE})
    return ", ".join(parts), acts


def can_act(access_text):
    """Whether an item's 'access' text, as written by describe, says it can send or change."""
    return "(can " in (access_text or "")
