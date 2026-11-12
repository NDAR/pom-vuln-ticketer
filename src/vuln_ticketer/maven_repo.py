"""Maven repository lookups: published versions, and what a Spring Boot BOM manages."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass

import requests

from . import versions as V
from .pom import BOOT_BOM, BOOT_GROUP, PomError, parse_pom

DEFAULT_BASE_URL = "https://repo1.maven.org/maven2"
MAX_BOOT_FETCHES = 25
MAX_BOM_CHECKS = 3


class MavenRepoUnavailable(Exception):
    pass


class MavenRepo:
    def __init__(self, base_url: str = DEFAULT_BASE_URL, session: requests.Session | None = None, timeout: float = 10):
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self._cache: dict[str, str | None] = {}

    def _get(self, path: str) -> str | None:
        if path not in self._cache:
            try:
                resp = self.session.get(f"{self.base_url}/{path}", timeout=self.timeout)
            except requests.RequestException as e:
                raise MavenRepoUnavailable(str(e)) from e
            if resp.status_code == 404:
                self._cache[path] = None
            elif resp.status_code >= 400:
                raise MavenRepoUnavailable(f"{resp.status_code} for {path}")
            else:
                self._cache[path] = resp.text
        return self._cache[path]

    def versions(self, group: str, artifact: str) -> list[str]:
        """Published release versions, ascending. Empty when the artifact is unknown."""
        text = self._get(f"{group.replace('.', '/')}/{artifact}/maven-metadata.xml")
        if text is None:
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        found = [v.text.strip() for v in root.iter("version") if v.text and v.text.strip()]
        return V.sort_versions(v for v in found if not V.is_prerelease(v))

    def fetch_pom(self, group: str, artifact: str, version: str) -> str | None:
        return self._get(f"{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom")


@dataclass(frozen=True)
class ManagedEntry:
    version: str
    property: str | None  # Boot-level property that sets this version
    bom: tuple[str, str] | None  # nested BOM that supplied the entry


class BootBom:
    def __init__(self, repo: MavenRepo):
        self.repo = repo
        self._managed: dict[str, dict[tuple[str, str], ManagedEntry]] = {}
        self._boms: dict[tuple[str, str, str], dict[tuple[str, str], str]] = {}

    def _bom_entries(self, group: str, artifact: str, version: str, depth: int = 1) -> dict[tuple[str, str], str]:
        """(group, artifact) -> version managed by a BOM, following its own imports one level."""
        key = (group, artifact, version)
        if key not in self._boms:
            entries: dict[tuple[str, str], str] = {}
            text = self.repo.fetch_pom(group, artifact, version)
            try:
                pom = parse_pom(text, f"{artifact}-{version}.pom") if text else None
            except PomError:
                pom = None
            for dep in pom.managed if pom else []:
                if dep.version is None:
                    continue
                if dep.scope == "import":
                    if depth > 0:
                        for k, v in self._bom_entries(dep.group, dep.artifact, dep.version, depth - 1).items():
                            entries.setdefault(k, v)
                else:
                    entries[(dep.group, dep.artifact)] = dep.version
            self._boms[key] = entries
        return self._boms[key]

    def managed(self, boot_version: str) -> dict[tuple[str, str], ManagedEntry]:
        if boot_version not in self._managed:
            direct: dict[tuple[str, str], ManagedEntry] = {}
            nested: dict[tuple[str, str], ManagedEntry] = {}
            text = self.repo.fetch_pom(BOOT_GROUP, BOOT_BOM, boot_version)
            try:
                pom = parse_pom(text, f"{BOOT_BOM}-{boot_version}.pom") if text else None
            except PomError:
                pom = None
            for dep in pom.managed if pom else []:
                if dep.version is None:
                    continue
                if dep.scope == "import":
                    for k, v in self._bom_entries(dep.group, dep.artifact, dep.version).items():
                        nested.setdefault(k, ManagedEntry(v, dep.property, (dep.group, dep.artifact)))
                else:
                    direct[(dep.group, dep.artifact)] = ManagedEntry(dep.version, dep.property, None)
            self._managed[boot_version] = {**nested, **direct}
        return self._managed[boot_version]

    def lowest_boot_managing(self, group: str, artifact: str, target: str, current_boot: str) -> str | None:
        """Lowest Boot release above current_boot, same major, that manages artifact at >= target."""
        newer = [v for v in self.repo.versions(BOOT_GROUP, BOOT_BOM)
                 if V.compare(v, current_boot) > 0 and V.major(v) == V.major(current_boot)]
        line = V.minor_line(current_boot)
        candidates = [v for v in newer if V.minor_line(v) == line] + [v for v in newer if V.minor_line(v) != line]
        for boot_version in candidates[:MAX_BOOT_FETCHES]:
            entry = self.managed(boot_version).get((group, artifact))
            if entry and V.compare(entry.version, target) >= 0:
                return boot_version
        return None

    def override_value(self, entry: ManagedEntry, group: str, artifact: str, target: str) -> str | None:
        """Value to give entry.property so that artifact resolves to >= target."""
        if not entry.property:
            return None
        if entry.bom is None:
            return target
        newer = [v for v in self.repo.versions(*entry.bom) if V.compare(v, target) >= 0]
        line = V.minor_line(target)
        candidates = [v for v in newer if V.minor_line(v) == line] + [v for v in newer if V.minor_line(v) != line]
        for bom_version in candidates[:MAX_BOM_CHECKS]:
            managed = self._bom_entries(*entry.bom, bom_version).get((group, artifact))
            if managed and V.compare(managed, target) >= 0:
                return bom_version
        return None
