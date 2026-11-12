"""POM parsing: just enough of the Maven model to locate where a version is set."""
from __future__ import annotations

import posixpath
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable

_PROP = re.compile(r"^\$\{([^}]+)\}$")
BOOT_GROUP = "org.springframework.boot"
BOOT_PARENT = "spring-boot-starter-parent"
BOOT_BOM = "spring-boot-dependencies"


class PomError(Exception):
    pass


@dataclass
class Dep:
    group: str
    artifact: str
    version_raw: str | None
    version: str | None
    property: str | None
    scope: str | None = None
    type: str | None = None


@dataclass
class Pom:
    path: str
    group: str | None
    artifact: str
    version: str | None
    parent: Dep | None
    properties: dict[str, str]
    dependencies: list[Dep]
    managed: list[Dep]
    modules: list[str] = field(default_factory=list)


def _strip_ns(root: ET.Element) -> None:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]


def _text(el: ET.Element | None, tag: str) -> str | None:
    child = el.find(tag) if el is not None else None
    return child.text.strip() if child is not None and child.text and child.text.strip() else None


def resolve_value(raw: str | None, props: dict[str, str]) -> tuple[str | None, str | None]:
    """Return (resolved version, property name) for a raw <version> value."""
    if raw is None:
        return None, None
    m = _PROP.match(raw)
    if not m:
        return (None if "${" in raw else raw), None
    name, value = m.group(1), props.get(m.group(1))
    for _ in range(5):  # properties may point at other properties
        inner = _PROP.match(value) if value else None
        if not inner:
            break
        value = props.get(inner.group(1))
    return (None if value is None or "${" in value else value), name


def _dep(el: ET.Element, props: dict[str, str]) -> Dep | None:
    group, artifact = _text(el, "groupId"), _text(el, "artifactId")
    if not group or not artifact:
        return None
    raw = _text(el, "version")
    version, prop = resolve_value(raw, props)
    return Dep(group, artifact, raw, version, prop, _text(el, "scope"), _text(el, "type"))


def _resolve_all(pom: Pom, props: dict[str, str]) -> None:
    for d in pom.dependencies + pom.managed:
        d.version, d.property = resolve_value(d.version_raw, props)


def _props_for(pom: Pom, inherited: dict[str, str] | None = None) -> dict[str, str]:
    props = dict(inherited or {})
    props.update(pom.properties)
    if pom.version:
        props["project.version"] = pom.version
    return props


def parse_pom(xml_text: str, path: str) -> Pom:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise PomError(f"{path}: {e}") from e
    _strip_ns(root)
    if root.tag != "project":
        raise PomError(f"{path}: root element is <{root.tag}>, not <project>")

    parent_el = root.find("parent")
    parent = _dep(parent_el, {}) if parent_el is not None else None
    props_el = root.find("properties")
    properties = {c.tag: (c.text or "").strip() for c in props_el} if props_el is not None else {}
    pom = Pom(
        path=path,
        group=_text(root, "groupId") or (parent.group if parent else None),
        artifact=_text(root, "artifactId") or "",
        version=_text(root, "version") or (parent.version_raw if parent else None),
        parent=parent,
        properties=properties,
        dependencies=[],
        managed=[],
        modules=[m.text.strip() for m in root.findall("modules/module") if m.text and m.text.strip()],
    )
    props = _props_for(pom)
    pom.dependencies = [d for el in root.findall("dependencies/dependency") if (d := _dep(el, props))]
    pom.managed = [d for el in root.findall("dependencyManagement/dependencies/dependency") if (d := _dep(el, props))]
    return pom


@dataclass
class Project:
    poms: list[Pom]

    @property
    def root(self) -> Pom:
        return self.poms[0]

    @staticmethod
    def _matches(dep: Dep, group: str | None, artifact: str) -> bool:
        return dep.artifact == artifact and (group is None or dep.group == group)

    def find_direct(self, group: str | None, artifact: str) -> tuple[Pom, Dep] | None:
        for pom in self.poms:
            for dep in pom.dependencies:
                if dep.version_raw is not None and self._matches(dep, group, artifact):
                    return pom, dep
        return None

    def find_managed(self, group: str | None, artifact: str) -> tuple[Pom, Dep] | None:
        for pom in self.poms:
            for dep in pom.managed:
                if dep.scope != "import" and dep.version_raw is not None and self._matches(dep, group, artifact):
                    return pom, dep
        return None

    def property_owner(self, name: str) -> Pom | None:
        return next((pom for pom in self.poms if name in pom.properties), None)

    def boot(self) -> tuple[str, bool] | None:
        """(Spring Boot version, True if Boot is the parent / False if its BOM is imported)."""
        parent = self.root.parent
        if parent and parent.group == BOOT_GROUP and parent.artifact == BOOT_PARENT and parent.version:
            return parent.version, True
        for dep in self.root.managed:
            if dep.scope == "import" and dep.group == BOOT_GROUP and dep.artifact == BOOT_BOM and dep.version:
                return dep.version, False
        return None


def load_project(fetch: Callable[[str], str | None], pom_path: str = "pom.xml") -> Project | None:
    """Load the root POM and every POM reachable through <modules>. None if the root is unreadable."""
    text = fetch(pom_path)
    if text is None:
        return None
    try:
        root = parse_pom(text, pom_path)
    except PomError:
        return None
    poms, seen = [root], {pom_path}

    def walk(parent: Pom, inherited: dict[str, str]) -> None:
        base = posixpath.dirname(parent.path)
        for module in parent.modules:
            path = posixpath.normpath(posixpath.join(base, module))
            if not path.endswith(".xml"):
                path = posixpath.join(path, "pom.xml")
            if path in seen:
                continue
            seen.add(path)
            module_text = fetch(path)
            if module_text is None:
                continue
            try:
                child = parse_pom(module_text, path)
            except PomError:
                continue
            props = _props_for(child, inherited)
            _resolve_all(child, props)
            poms.append(child)
            walk(child, props)

    walk(root, _props_for(root))
    return Project(poms)
