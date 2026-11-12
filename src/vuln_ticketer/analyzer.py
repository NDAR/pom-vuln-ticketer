"""Rule-based analysis: which POM change fixes each vulnerable artifact."""
from __future__ import annotations

from . import versions as V
from .maven_repo import BootBom
from .models import Suggestion
from .pom import BOOT_BOM, BOOT_GROUP, BOOT_PARENT, Project

UNKNOWN_GROUP = "UNKNOWN"
NOTE_TRANSITIVE = "Transitive dependency; pinned via dependencyManagement."


def _base(v: str) -> str:
    """Version without its flavour: "32.0.1-jre" -> "32.0.1"."""
    fl = V.flavour(v)
    return v[: len(v) - len(fl)].rstrip(".-_") if fl else v


def select_target(installed: str, fixed: list[str], published: list[str] | None) -> tuple[str | None, bool]:
    """Pick the version to upgrade to. Returns (target, verified against the repository)."""
    floor = _base(installed)
    candidates = V.sort_versions(
        f for f in fixed
        if f and f != "NotAvailable" and not V.is_prerelease(f) and V.compare(_base(f), floor) > 0
    )
    if not candidates:
        return None, False
    same_minor = [c for c in candidates if V.minor_line(c) == V.minor_line(installed)]
    same_major = [c for c in candidates if V.major(c) == V.major(installed)]
    candidate = (same_minor or same_major or candidates)[0]
    if published is None:
        return candidate, False
    wanted = V.flavour(installed)
    for p in V.sort_versions(published):
        if (not V.is_prerelease(p) and V.flavour(p) == wanted and V.major(p) == V.major(candidate)
                and V.compare(_base(p), _base(candidate)) >= 0):
            return p, True
    return candidate, False


def _dependency_xml(group: str, artifact: str, version: str, extra: str = "") -> str:
    return (f"<dependency>\n  <groupId>{group}</groupId>\n  <artifactId>{artifact}</artifactId>\n"
            f"  <version>{version}</version>\n{extra}</dependency>")


def _pin_xml(group: str, artifact: str, version: str) -> str:
    inner = _dependency_xml(group, artifact, version).replace("\n", "\n    ")
    return f"<dependencyManagement>\n  <dependencies>\n    {inner}\n  </dependencies>\n</dependencyManagement>"


def _boot_xml(version: str, is_parent: bool) -> str:
    if is_parent:
        return (f"<parent>\n  <groupId>{BOOT_GROUP}</groupId>\n  <artifactId>{BOOT_PARENT}</artifactId>\n"
                f"  <version>{version}</version>\n</parent>")
    return _dependency_xml(BOOT_GROUP, BOOT_BOM, version, "  <type>pom</type>\n  <scope>import</scope>\n")


def _adopt_group(artifact: str, project: Project | None, managed: dict) -> str | None:
    groups = {g for g, a in managed if a == artifact}
    for pom in project.poms if project else []:
        groups |= {d.group for d in pom.dependencies + pom.managed if d.artifact == artifact}
    return groups.pop() if len(groups) == 1 else None


def classify(group: str | None, artifact: str, installed: str, target: str,
             project: Project | None, boot_bom: BootBom | None) -> Suggestion:
    """Decide where in the POM the version of one artifact is controlled. First match wins."""
    boot = project.boot() if project else None
    boot_managed = boot_bom.managed(boot[0]) if boot and boot_bom else {}
    if group is None:
        group = _adopt_group(artifact, project, boot_managed)
    root_path = project.root.path if project else "pom.xml"

    def suggestion(kind: str, pom_file: str, section: str, snippet: str, **extra) -> Suggestion:
        return Suggestion(group=group, artifact=artifact, current=[installed], target=target, kind=kind,
                          pom_file=pom_file, section=section, snippet=snippet, cves=[], verified=True, **extra)

    def pin(note: str) -> Suggestion:
        return suggestion("pin", root_path, "dependencyManagement",
                          _pin_xml(group or UNKNOWN_GROUP, artifact, target), note=note)

    if group is None:
        return pin(f"The group of {artifact} could not be determined; replace {UNKNOWN_GROUP} with its groupId. "
                   + NOTE_TRANSITIVE)

    # Cases 1 and 2: the project sets the version itself.
    for hit, kind, section in ((project.find_direct(group, artifact) if project else None, "direct", "dependencies"),
                               (project.find_managed(group, artifact) if project else None, "managed", "dependencyManagement")):
        if not hit:
            continue
        pom, dep = hit
        if dep.property:
            owner = project.property_owner(dep.property)
            if owner:
                return suggestion("property", owner.path, "properties", f"<{dep.property}>{target}</{dep.property}>")
            return pin(f"Version comes from ${{{dep.property}}}, which is not defined in this repository; "
                       "pin shown instead.")
        if dep.version:
            return suggestion(kind, pom.path, section, _dependency_xml(dep.group, dep.artifact, target))
        return pin(f"Version expression {dep.version_raw} could not be resolved; pin shown instead.")

    # Case 3: Spring Boot manages the version.
    entry = boot_managed.get((group, artifact))
    if entry and boot and boot_bom:
        boot_version, is_parent = boot
        upgrade = boot_bom.lowest_boot_managing(group, artifact, target, boot_version)
        override = boot_bom.override_value(entry, group, artifact, target) if is_parent else None
        if upgrade:
            return suggestion("boot", root_path, "parent" if is_parent else "dependencyManagement",
                              _boot_xml(upgrade, is_parent), boot_upgrade=upgrade,
                              override_property=f"{entry.property}={override}" if override else None)
        if override:
            return suggestion("boot", root_path, "properties", f"<{entry.property}>{override}</{entry.property}>")

    # Case 4: transitive or unmanaged.
    return pin(NOTE_TRANSITIVE)
