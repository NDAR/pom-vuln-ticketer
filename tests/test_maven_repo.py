import re

import pytest
import requests
import responses
from fakes import BASE, DATABIND, SNAKEYAML, maven_files

from vuln_ticketer.maven_repo import BootBom, ManagedEntry, MavenRepo, MavenRepoUnavailable

G, A = "org.springframework.boot", "spring-boot-dependencies"


@pytest.fixture
def repo():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for path, body in maven_files().items():
            rsps.add(responses.GET, f"{BASE}/{path}", body=body)
        rsps.add(responses.GET, re.compile(f"{BASE}/io/netty/netty-bom/.*"), status=404)
        rsps.add(responses.GET, f"{BASE}/org/x/y/maven-metadata.xml", status=503)
        rsps.add(responses.GET, f"{BASE}/org/x/z/maven-metadata.xml", body=requests.ConnectionError("boom"))
        r = MavenRepo()
        r.rsps = rsps
        yield r


def test_versions_sorted_no_prerelease(repo):
    assert repo.versions(G, A) == ["3.1.5", "3.2.1", "3.2.5", "3.2.12", "3.3.0", "4.0.0"]


def test_versions_404_is_empty(repo):
    repo.rsps.add(responses.GET, f"{BASE}/x/nope/maven-metadata.xml", status=404)
    assert repo.versions("x", "nope") == []


@pytest.mark.parametrize("artifact", ["y", "z"])
def test_unavailable(repo, artifact):
    with pytest.raises(MavenRepoUnavailable):
        repo.versions("org.x", artifact)


def test_cache(repo):
    repo.versions(G, A)
    repo.versions(G, A)
    assert len(repo.rsps.calls) == 1


def test_fetch_pom_404_is_none(repo):
    repo.rsps.add(responses.GET, f"{BASE}/x/y/1/y-1.pom", status=404)
    assert repo.fetch_pom("x", "y", "1") is None


@responses.activate
def test_custom_base_url():
    responses.add(responses.GET, "https://nexus.corp/repo/org/a/b/maven-metadata.xml",
                  body="<metadata><versioning><versions><version>1</version></versions></versioning></metadata>")
    assert MavenRepo("https://nexus.corp/repo/").versions("org.a", "b") == ["1"]


def test_managed_direct_and_nested(repo):
    m = BootBom(repo).managed("3.2.1")
    assert m[SNAKEYAML] == ManagedEntry("2.2", "snakeyaml.version", None)
    assert m[DATABIND] == ManagedEntry("2.15.3", "jackson-bom.version", ("com.fasterxml.jackson", "jackson-bom"))


def test_managed_unknown_boot_version_is_empty(repo):
    repo.rsps.add(responses.GET, f"{BASE}/org/springframework/boot/spring-boot-dependencies/9.9.9/spring-boot-dependencies-9.9.9.pom", status=404)
    assert BootBom(repo).managed("9.9.9") == {}


def test_lowest_boot_same_minor(repo):
    assert BootBom(repo).lowest_boot_managing(*DATABIND, "2.15.4", "3.2.1") == "3.2.5"


def test_lowest_boot_next_minor(repo):
    assert BootBom(repo).lowest_boot_managing(*DATABIND, "2.16.0", "3.2.1") == "3.3.0"


def test_lowest_boot_none_in_major(repo):
    assert BootBom(repo).lowest_boot_managing(*DATABIND, "2.99.0", "3.2.1") is None  # never 4.0.0


def test_override_direct(repo):
    bom = BootBom(repo)
    assert bom.override_value(bom.managed("3.2.1")[SNAKEYAML], *SNAKEYAML, "2.3") == "2.3"


def test_override_nested_bom(repo):
    bom = BootBom(repo)
    assert bom.override_value(bom.managed("3.2.1")[DATABIND], *DATABIND, "2.15.4") == "2.15.4"


def test_override_nested_bom_none_available(repo):
    bom = BootBom(repo)
    assert bom.override_value(bom.managed("3.2.1")[DATABIND], *DATABIND, "2.99.0") is None


def test_override_without_property(repo):
    assert BootBom(repo).override_value(ManagedEntry("1.0", None, None), "g", "a", "1.1") is None


def test_transient_failure_is_retried():
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, f"{BASE}/org/a/b/maven-metadata.xml", status=503)
        rsps.add(responses.GET, f"{BASE}/org/a/b/maven-metadata.xml",
                 body="<metadata><versioning><versions><version>1</version></versions></versioning></metadata>")
        assert MavenRepo().versions("org.a", "b") == ["1"]


def test_stops_calling_a_repository_that_keeps_failing():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add(responses.GET, re.compile(f"{BASE}/.*"), status=503)
        r = MavenRepo()
        for artifact in "abcde":
            with pytest.raises(MavenRepoUnavailable):
                r.versions("org.x", artifact)
        assert len(rsps.calls) == 6  # three lookups tried twice each, then the circuit opens


def test_boot_search_fetches_only_the_relevant_nested_bom():
    from fakes import FakeRepo

    repo = FakeRepo()
    bom = BootBom(repo)
    bom.managed("3.2.1")
    repo.requested.clear()
    assert bom.lowest_boot_managing(*DATABIND, "2.16.0", "3.2.1") == "3.3.0"
    assert not [p for p in repo.requested if "netty-bom" in p]
    repo.requested.clear()
    assert bom.lowest_boot_managing(*SNAKEYAML, "2.3", "3.2.1") == "3.2.5"
    assert not [p for p in repo.requested if "-bom/" in p]  # direct entry: no nested BOM needed at all
