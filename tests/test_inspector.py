import copy
import json

import boto3
import pytest
from botocore.stub import Stubber
from fakes import FIXTURES

from vuln_ticketer.inspector import list_findings, scan_ready
from vuln_ticketer.models import Image

IMG = Image("orders", "orders-svc", "sha256:aaa", "111111111111.dkr.ecr.us-east-1.amazonaws.com/orders-svc:abc123d")
COVERAGE_FILTER = {"filterCriteria": {"ecrRepositoryName": [{"comparison": "EQUALS", "value": "orders-svc"}]}}
FINDINGS_FILTER = {"filterCriteria": {
    "ecrImageHash": [{"comparison": "EQUALS", "value": "sha256:aaa"}],
    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
    "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
    "severity": [{"comparison": "EQUALS", "value": "CRITICAL"}, {"comparison": "EQUALS", "value": "HIGH"}],
}}


def load(name):
    return json.loads((FIXTURES / name).read_text())


def finding(fixture, **pkg_over):
    """A finding from a fixture, trimmed to the fields the API model requires plus what we read."""
    raw = load(fixture)
    pkg = {**raw["packageVulnerabilityDetails"]["vulnerablePackages"][0], **pkg_over}
    pkg = {k: v for k, v in pkg.items() if v is not None}
    return {
        "awsAccountId": raw["awsAccountId"], "findingArn": raw["findingArn"], "type": raw["type"],
        "severity": raw["severity"], "status": raw["status"], "title": raw["title"],
        "description": raw["description"], "firstObservedAt": "2026-01-01T00:00:00Z",
        "lastObservedAt": "2026-01-01T00:00:00Z", "remediation": {"recommendation": {"text": "upgrade"}},
        "resources": [{"type": "AWS_ECR_CONTAINER_IMAGE", "id": raw["resources"][0]["id"]}],
        "packageVulnerabilityDetails": {
            "vulnerabilityId": raw["packageVulnerabilityDetails"]["vulnerabilityId"],
            "source": raw["packageVulnerabilityDetails"]["source"],
            "vulnerablePackages": [pkg],
        },
    }


def coverage(reason="SUCCESSFUL", status="ACTIVE", digest="sha256:aaa"):
    rec = copy.deepcopy(load("inspector_coverage.json"))
    rec["scanStatus"] = {"statusCode": status, "reason": reason}
    rec["resourceId"] = rec["resourceId"].rsplit("/", 1)[0] + "/" + digest
    return rec


@pytest.fixture
def client():
    c = boto3.client("inspector2", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x")
    with Stubber(c) as stub:
        c.stub = stub
        yield c
        stub.assert_no_pending_responses()


def test_scan_ready_true(client):
    client.stub.add_response("list_coverage", {"coveredResources": [coverage()]}, COVERAGE_FILTER)
    assert scan_ready(client, [IMG]) is True


def test_scan_pending(client):
    client.stub.add_response("list_coverage", {"coveredResources": [coverage("PENDING_INITIAL_SCAN")]}, COVERAGE_FILTER)
    assert scan_ready(client, [IMG]) is False


def test_scan_no_record(client):
    client.stub.add_response("list_coverage", {"coveredResources": []}, COVERAGE_FILTER)
    assert scan_ready(client, [IMG]) is False


def test_scan_other_digest_does_not_count(client):
    client.stub.add_response("list_coverage", {"coveredResources": [coverage(digest="sha256:old")]}, COVERAGE_FILTER)
    assert scan_ready(client, [IMG]) is False


def test_scan_ready_paginates(client):
    client.stub.add_response("list_coverage", {"coveredResources": [coverage(digest="sha256:old")], "nextToken": "t"}, COVERAGE_FILTER)
    client.stub.add_response("list_coverage", {"coveredResources": [coverage()]}, {**COVERAGE_FILTER, "nextToken": "t"})
    assert scan_ready(client, [IMG]) is True


def test_scan_ready_no_images(client):
    assert scan_ready(client, []) is True


def test_maps_java_fixture(client):
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_java.json")]}, FINDINGS_FILTER)
    f = list_findings(client, [IMG])[0]
    assert (f.group, f.artifact, f.version) == ("com.fasterxml.jackson.core", "jackson-databind", "2.15.2")
    assert (f.cve, f.severity, f.is_java, f.fixed_versions, f.services) == ("CVE-2023-35116", "HIGH", True, ["2.15.4"], ["orders"])
    assert f.file_path == "app.jar/BOOT-INF/lib/jackson-databind-2.15.2.jar" and f.title.startswith("CVE-2023-35116")


def test_maps_os_fixture(client):
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_os.json")]}, FINDINGS_FILTER)
    f = list_findings(client, [IMG])[0]
    assert f.is_java is False and f.artifact == "openssl" and f.group is None and f.severity == "CRITICAL"


def test_group_missing_uses_jar_name(client):
    client.stub.add_response("list_findings", {"findings": [finding(
        "inspector_finding_java.json", name="jackson-databind")]}, FINDINGS_FILTER)
    f = list_findings(client, [IMG])[0]
    assert f.group is None and f.artifact == "jackson-databind"


def test_group_missing_and_versioned_name_without_path(client):
    client.stub.add_response("list_findings", {"findings": [finding(
        "inspector_finding_java.json", name="jackson-databind-2.15.2", filePath=None)]}, FINDINGS_FILTER)
    f = list_findings(client, [IMG])[0]
    assert f.group is None and f.artifact == "jackson-databind"


@pytest.mark.parametrize("raw,exp", [("2.15.4, 2.16.1", ["2.15.4", "2.16.1"]), ("NotAvailable", []), (None, [])])
def test_fixed_versions_parsing(client, raw, exp):
    client.stub.add_response("list_findings", {"findings": [finding(
        "inspector_finding_java.json", fixedInVersion=raw)]}, FINDINGS_FILTER)
    assert list_findings(client, [IMG])[0].fixed_versions == exp


def test_findings_paginate(client):
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_java.json")], "nextToken": "t"}, FINDINGS_FILTER)
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_os.json")]}, {**FINDINGS_FILTER, "nextToken": "t"})
    assert len(list_findings(client, [IMG])) == 2


def test_merge_across_images(client):
    other = Image("billing", "billing-svc", "sha256:bbb", "uri")
    other_filter = copy.deepcopy(FINDINGS_FILTER)
    other_filter["filterCriteria"]["ecrImageHash"][0]["value"] = "sha256:bbb"
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_java.json")]}, FINDINGS_FILTER)
    client.stub.add_response("list_findings", {"findings": [finding("inspector_finding_java.json")]}, other_filter)
    found = list_findings(client, [IMG, other])
    assert len(found) == 1 and found[0].services == ["billing", "orders"]
