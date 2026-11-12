import pytest
from fakes import (DATABIND, GUAVA, SNAKEYAML, FakeRepo, fixture_fetch, fixture_fetch_dir, java_finding as f,
                   make_deployment, os_finding)

from vuln_ticketer.analyzer import analyze
from vuln_ticketer.pom import load_project


@pytest.fixture
def dep():
    return make_deployment()


@pytest.fixture
def repo():
    return FakeRepo()


@pytest.fixture
def simple():
    return load_project(fixture_fetch("simple.xml"))


def test_merges_same_artifact(dep, simple, repo):
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1", "HIGH"),
                      f(DATABIND, "2.15.3", ["2.15.4"], "CVE-2", "CRITICAL")], simple, repo)
    assert len(r.suggestions) == 1 and r.suggestions[0].cves == [("CVE-2", "CRITICAL"), ("CVE-1", "HIGH")]


def test_highest_target_wins(dep, simple, repo):
    r = analyze(dep, [f(DATABIND, "2.15.2", ["2.15.3"], "CVE-1"), f(DATABIND, "2.15.2", ["2.15.4"], "CVE-2")], simple, repo)
    assert r.suggestions[0].target == "2.15.4"


def test_two_installed_versions(dep, simple, repo):
    r = analyze(dep, [f(GUAVA, "31.1-jre", ["32.0.1"], "CVE-1"), f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-1")], simple, repo)
    assert len(r.suggestions) == 1
    assert r.suggestions[0].current == ["31.1-jre", "32.0.0-jre"] and r.suggestions[0].target == "32.0.1-jre"
    assert r.suggestions[0].cves == [("CVE-1", "HIGH")] and len(r.finding_keys) == 2


def test_no_fix_and_non_pom(dep, simple, repo):
    r = analyze(dep, [f(GUAVA, "32.0.0-jre", ["NotAvailable"], "CVE-1"), os_finding("openssl", "CVE-9", "CRITICAL")], simple, repo)
    assert r.suggestions == [] and [x.cve for x in r.no_fix] == ["CVE-1"] and [x.cve for x in r.non_pom] == ["CVE-9"]
    assert r.counts() == {"total": 2, "critical": 1, "high": 1}


def test_headline(dep, repo):
    project = load_project(fixture_fetch_dir("multi"))  # Boot parent 3.2.1; snakeyaml and jackson managed by Boot
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1"), f(SNAKEYAML, "2.2", ["2.3"], "CVE-2"),
                      f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-3", "CRITICAL")], project, repo)
    assert r.headline == "Upgrading spring-boot-starter-parent 3.2.1 → 3.2.5 resolves 2 of 3 findings."
    assert [s.kind for s in r.suggestions] == ["boot", "boot", "pin"]  # boot first, even over a CRITICAL pin
    assert {s.boot_upgrade for s in r.suggestions[:2]} == {"3.2.5"}


def test_headline_aligns_to_highest_boot_version(dep, repo):
    project = load_project(fixture_fetch_dir("multi"))
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.16.0"], "CVE-1"), f(SNAKEYAML, "2.2", ["2.3"], "CVE-2")], project, repo)
    assert r.headline == "Upgrading spring-boot-starter-parent 3.2.1 → 3.3.0 resolves 2 of 2 findings."
    assert all(s.boot_upgrade == "3.3.0" and "<version>3.3.0</version>" in s.snippet for s in r.suggestions)


def test_headline_for_imported_bom(dep, repo):
    project = load_project(fixture_fetch("bom_import.xml"))
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1"), f(SNAKEYAML, "1.33", ["2.2"], "CVE-2")], project, repo)
    assert r.headline == "Upgrading spring-boot-dependencies 3.1.5 → 3.2.5 resolves 2 of 2 findings."


def test_single_boot_suggestion_has_no_headline(dep, simple, repo):
    assert analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1")], simple, repo).headline is None


def test_severity_then_name_ordering(dep, simple, repo):
    r = analyze(dep, [f(("org.example", "obscure"), "1.0", ["1.1"], "CVE-1", "HIGH"),
                      f(("org.apache.commons", "commons-text"), "1.9", ["1.10.0"], "CVE-2", "HIGH"),
                      f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-3", "CRITICAL")], simple, repo)
    assert [s.artifact for s in r.suggestions] == ["guava", "commons-text", "obscure"]


def test_repo_down(dep, simple):
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1")], simple, FakeRepo(down=True))
    assert r.suggestions[0].verified is False and r.suggestions[0].kind == "pin" and r.headline is None
    assert r.suggestions[0].target == "2.15.4"


def test_pom_missing(dep, repo):
    r = analyze(dep, [f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-1")], None, repo)
    assert r.pom_missing and r.suggestions[0].kind == "pin"


def test_empty(dep, simple, repo):
    r = analyze(dep, [], simple, repo)
    assert r.suggestions == [] and r.finding_keys == [] and r.counts()["total"] == 0 and r.pom_missing is False


def test_finding_keys_sorted(dep, simple, repo):
    findings = [os_finding("openssl", "CVE-9"), f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-1"), f(DATABIND, "2.15.3", [], "CVE-2")]
    assert analyze(dep, findings, simple, repo).finding_keys == sorted(x.key for x in findings)


def test_one_failed_lookup_degrades_only_that_artifact(dep, simple):
    repo = FakeRepo(fail_paths=("commons-text/maven-metadata.xml",))
    r = analyze(dep, [f(("org.apache.commons", "commons-text"), "1.9", ["1.10.0"], "CVE-1"),
                      f(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-2"),
                      f(DATABIND, "2.15.3", ["2.15.4"], "CVE-3")], simple, repo)
    by = {s.artifact: s for s in r.suggestions}
    assert by["commons-text"].verified is False and by["commons-text"].kind == "property"
    assert by["guava"].verified is True and by["jackson-databind"].kind == "boot"


def test_project_boot_property_is_not_in_headline(dep, repo):
    project = load_project(fixture_fetch("boot_prop_override.xml"))
    r = analyze(dep, [f(DATABIND, "2.15.3", ["2.15.4"], "CVE-1"), f(SNAKEYAML, "2.2", ["2.3"], "CVE-2")], project, repo)
    assert r.headline is None and {s.kind for s in r.suggestions} == {"property"}
