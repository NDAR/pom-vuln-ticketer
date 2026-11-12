from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field


@dataclass
class Image:
    service: str
    ecr_repo: str
    digest: str
    uri: str


@dataclass
class Deployment:
    repo: str
    branch: str
    commit: str
    pipeline: str
    execution_id: str
    images: list[Image]

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Deployment:
        return cls(**{**d, "images": [Image(**i) for i in d["images"]]})


@dataclass
class Finding:
    group: str | None
    artifact: str
    version: str
    fixed_versions: list[str]
    cve: str
    severity: str
    title: str
    is_java: bool
    file_path: str
    services: list[str]

    @property
    def key(self) -> str:
        return f"{self.group or '?'}:{self.artifact}@{self.version}:{self.cve}"


@dataclass
class Suggestion:
    group: str | None
    artifact: str
    current: list[str]
    target: str
    kind: str  # "direct" | "property" | "managed" | "boot" | "pin"
    pom_file: str
    section: str
    snippet: str
    cves: list[tuple[str, str]]  # (cve, severity), CRITICAL first
    verified: bool
    boot_upgrade: str | None = None
    override_property: str | None = None
    note: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> Suggestion:
        return cls(**{**d, "cves": [tuple(c) for c in d["cves"]]})


@dataclass
class Report:
    deployment: Deployment
    suggestions: list[Suggestion]
    no_fix: list[Finding]
    non_pom: list[Finding]
    headline: str | None
    finding_keys: list[str]
    pom_missing: bool

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Report:
        return cls(
            deployment=Deployment.from_dict(d["deployment"]),
            suggestions=[Suggestion.from_dict(s) for s in d["suggestions"]],
            no_fix=[Finding(**f) for f in d["no_fix"]],
            non_pom=[Finding(**f) for f in d["non_pom"]],
            headline=d["headline"],
            finding_keys=list(d["finding_keys"]),
            pom_missing=d["pom_missing"],
        )

    def counts(self) -> dict[str, int]:
        severities = [sev for s in self.suggestions for _, sev in s.cves]
        severities += [f.severity for f in self.no_fix + self.non_pom]
        critical = sum(1 for s in severities if s == "CRITICAL")
        return {"total": len(severities), "critical": critical, "high": len(severities) - critical}


@dataclass
class TicketPlan:
    action: str  # "create" | "update" | "close" | "none"
    summary: str = ""
    description: str = ""
    comment: str | None = None
    priority_severity: str | None = None  # "CRITICAL" | "HIGH"
