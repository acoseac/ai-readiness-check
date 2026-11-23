"""The small data model every check returns."""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

SEVERITIES = ("high", "medium", "low", "info")

# Full links, so they work from a report opened anywhere, not only next to a copy of the repo.
DOCS = "https://github.com/acoseac/ai-readiness-check/blob/main/docs/"


@dataclass
class Finding:
    id: str
    severity: str  # high, medium, low or info
    title: str
    why: str  # why it matters once an AI assistant is switched on
    fix: str  # what to do, in plain words
    items: list = field(default_factory=list)  # dicts with at least "name"
    sources: list = field(default_factory=list)  # official pages behind the advice

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")


@dataclass
class Result:
    platform: str  # "Google Workspace" or "Microsoft 365"
    tenant: str = ""
    started: str = field(default_factory=lambda: now())
    finished: str = ""
    findings: list = field(default_factory=list)
    summary: str = ""  # one line on how widely files are shared, whatever their names
    coverage: list = field(default_factory=list)  # what this run could and could not see
    errors: list = field(default_factory=list)

    def add(self, finding):
        if finding is not None:
            self.findings.append(finding)

    def sorted_findings(self):
        return sorted(self.findings, key=lambda f: (SEVERITIES.index(f.severity), f.id))

    def counts(self):
        return {s: sum(1 for f in self.findings if f.severity == s) for s in SEVERITIES}

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.sorted_findings()]
        return d


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
