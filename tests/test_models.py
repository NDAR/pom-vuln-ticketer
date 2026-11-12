import dataclasses
import json

from vuln_ticketer.models import Deployment, Finding, Image, Report, Suggestion


def _finding(**over):
    base = dict(group="com.fasterxml.jackson.core", artifact="jackson-databind", version="2.15.2",
                fixed_versions=["2.15.4"], cve="CVE-2023-1", severity="HIGH", title="t", is_java=True,
                file_path="app.jar/BOOT-INF/lib/jackson-databind-2.15.2.jar", services=["svc"])
    base.update(over)
    return Finding(**base)


def _report():
    dep = Deployment(repo="orders-svc", branch="main", commit="abc123def", pipeline="orders-pipeline",
                     execution_id="exec-1", images=[Image("orders", "orders-svc", "sha256:aaa", "uri")])
    sug = Suggestion(group="g", artifact="a", current=["1.0"], target="1.1", kind="direct", pom_file="pom.xml",
                     section="dependencies", snippet="<x/>", cves=[("A", "CRITICAL"), ("B", "HIGH")], verified=True,
                     boot_upgrade="3.2.5", override_property="p=1", note="n")
    return Report(deployment=dep, suggestions=[sug], no_fix=[_finding(cve="C", fixed_versions=[])],
                  non_pom=[_finding(cve="D", severity="CRITICAL", is_java=False, group=None, artifact="openssl")],
                  headline="h", finding_keys=["k1", "k2"], pom_missing=False)


def test_finding_key():
    f = _finding()
    assert f.key == "com.fasterxml.jackson.core:jackson-databind@2.15.2:CVE-2023-1"
    assert dataclasses.replace(f, group=None).key == "?:jackson-databind@2.15.2:CVE-2023-1"


def test_report_round_trip():
    report = _report()
    assert Report.from_dict(json.loads(json.dumps(report.to_dict()))) == report


def test_deployment_round_trip():
    dep = _report().deployment
    assert Deployment.from_dict(json.loads(json.dumps(dep.to_dict()))) == dep


def test_counts():
    assert _report().counts() == {"total": 4, "critical": 2, "high": 2}
