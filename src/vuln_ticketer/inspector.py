"""AWS Inspector gateway: is the image scanned yet, and what did the scan find."""
from __future__ import annotations

import re

from .log import get_logger
from .models import Finding, Image

log = get_logger("inspector")

JAVA_MANAGERS = {"JAR", "POM", "GRADLE", "POMPROPERTIES"}
SEVERITIES = ("CRITICAL", "HIGH")  # the only findings this tool handles
_JAR = re.compile(r"(?:^|/)([^/]+?)-(\d[^/]*)\.jar$")
_NAME_VERSION = re.compile(r"^(.+?)-\d[\w.\-]*$")


def _eq(value: str) -> dict:
    return {"comparison": "EQUALS", "value": value}


def _pages(method, key: str, **kwargs):
    token = None
    while True:
        page = method(**kwargs, **({"nextToken": token} if token else {}))
        yield from page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return


def scan_ready(client, images: list[Image]) -> bool:
    """True when Inspector has finished scanning every image."""
    for image in images:
        records = _pages(client.list_coverage, "coveredResources",
                         filterCriteria={"ecrRepositoryName": [_eq(image.ecr_repo)]})
        status = next((r.get("scanStatus", {}) for r in records if r.get("resourceId", "").endswith(image.digest)), None)
        if not status or status.get("statusCode") != "ACTIVE" or status.get("reason") != "SUCCESSFUL":
            # Logged so that an unexpected status (one that never becomes ready) is visible to operators.
            log.info("image scan not ready", extra={"ecrRepo": image.ecr_repo, "digest": image.digest,
                                                     "scanStatus": status})
            return False
    return True


def _coordinates(name: str, file_path: str, is_java: bool) -> tuple[str | None, str]:
    if not is_java:
        return None, name
    if ":" in name:
        group, artifact = name.split(":", 1)
        return group or None, artifact
    jar = _JAR.search(file_path)
    if jar:
        return None, jar.group(1)
    versioned = _NAME_VERSION.match(name)
    return None, versioned.group(1) if versioned else name


def _fixed_versions(raw: str | None) -> list[str]:
    return [v for v in re.split(r"[,\s]+", raw or "") if v and v != "NotAvailable"]


def list_findings(client, images: list[Image]) -> list[Finding]:
    """Active CRITICAL/HIGH package vulnerabilities on the images, one per vulnerable package."""
    merged: dict[str, Finding] = {}
    managers: dict[str, int] = {}
    for image in images:
        criteria = {
            "ecrImageHash": [_eq(image.digest)],
            "findingStatus": [_eq("ACTIVE")],
            "findingType": [_eq("PACKAGE_VULNERABILITY")],
            "severity": [_eq(s) for s in SEVERITIES],
        }
        for raw in _pages(client.list_findings, "findings", filterCriteria=criteria):
            details = raw.get("packageVulnerabilityDetails", {})
            for pkg in details.get("vulnerablePackages", []):
                manager = pkg.get("packageManager", "UNKNOWN")
                managers[manager] = managers.get(manager, 0) + 1
                is_java = manager in JAVA_MANAGERS
                file_path = pkg.get("filePath", "")
                group, artifact = _coordinates(pkg.get("name", ""), file_path, is_java)
                finding = Finding(
                    group=group, artifact=artifact, version=pkg.get("version", ""),
                    fixed_versions=_fixed_versions(pkg.get("fixedInVersion")),
                    cve=details.get("vulnerabilityId", ""), severity=raw.get("severity", ""),
                    title=raw.get("title", ""), is_java=is_java, file_path=file_path, services=[image.service],
                )
                existing = merged.get(finding.key)
                if existing:
                    existing.services = sorted(set(existing.services) | {image.service})
                else:
                    merged[finding.key] = finding
    # Logged so that a Java package manager this tool does not recognise is visible to operators.
    log.info("inspector findings read", extra={"findings": len(merged), "packageManagers": managers})
    return list(merged.values())
