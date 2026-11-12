"""Capture real Inspector records for one ECR image, for use as test fixtures.

Usage: probe_inspector.py <ecr-repo> <image-digest> [--region R]
"""
import argparse
import json
import re
import sys

import boto3

JAVA_MANAGERS = {"JAR", "POM", "GRADLE", "POMPROPERTIES"}


def _scrub(obj):
    return json.loads(re.sub(r"\b\d{12}\b", "111111111111", json.dumps(obj, default=str)))


def _pages(method, key, **kwargs):
    token = None
    while True:
        page = method(**kwargs, **({"nextToken": token} if token else {}))
        yield from page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ecr_repo")
    ap.add_argument("digest")
    ap.add_argument("--region")
    args = ap.parse_args(argv)
    client = boto3.client("inspector2", region_name=args.region)

    coverage = next(
        (c for c in _pages(client.list_coverage, "coveredResources",
                           filterCriteria={"ecrRepositoryName": [{"comparison": "EQUALS", "value": args.ecr_repo}]})
         if c.get("resourceId", "").endswith(args.digest)),
        None,
    )
    java = other = None
    managers: dict[str, int] = {}
    for f in _pages(client.list_findings, "findings", filterCriteria={
        "ecrImageHash": [{"comparison": "EQUALS", "value": args.digest}],
        "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
    }):
        for p in f.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", []):
            managers[p.get("packageManager", "?")] = managers.get(p.get("packageManager", "?"), 0) + 1
        pkgs = f.get("packageVulnerabilityDetails", {}).get("vulnerablePackages", [])
        if not pkgs:
            continue
        if pkgs[0].get("packageManager") in JAVA_MANAGERS:
            java = java or f
        else:
            other = other or f
    print(json.dumps(_scrub({"coverage": coverage, "java": java, "other": other, "packageManagers": managers}), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
