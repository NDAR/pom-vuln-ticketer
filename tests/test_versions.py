import pytest

from vuln_ticketer.versions import compare, flavour, is_prerelease, major, minor_line, sort_versions


@pytest.mark.parametrize("a,b,exp", [
    ("2.15.2", "2.15.4", -1), ("2.9", "2.10", -1), ("1.0", "1.0.0", 0),
    ("3.2.0-RC1", "3.2.0", -1), ("3.2.0-M1", "3.2.0-RC1", -1), ("3.2.0-SNAPSHOT", "3.2.0", -1),
    ("5.3.30.RELEASE", "5.3.30", 0), ("2.7.18", "3.0.0", -1), ("1.2.3.Final", "1.2.4.Final", -1),
    ("32.0.0-jre", "32.1.3-jre", -1), ("1.0-sp1", "1.0", 1), ("32.0.1", "32.0.0-jre", 1),
])
def test_compare(a, b, exp):
    assert compare(a, b) == exp and compare(b, a) == -exp


def test_sort():
    assert sort_versions(["2.10", "2.9", "2.9.1"]) == ["2.9", "2.9.1", "2.10"]


@pytest.mark.parametrize("v,exp", [
    ("3.2.0-RC1", True), ("3.2.0-M2", True), ("1.0-SNAPSHOT", True), ("2.0.0-alpha1", True),
    ("2.0.0-beta", True), ("3.2.0", False), ("5.3.30.RELEASE", False), ("32.0.0-jre", False),
    ("32.0.0-android", False), ("1.2.3.Final", False), ("2.1.0.redhat-1", False),
])
def test_is_prerelease(v, exp):
    assert is_prerelease(v) is exp


def test_flavour():
    assert flavour("32.0.0-jre") == "jre" and flavour("32.0.0-android") == "android"
    assert flavour("2.1.0.redhat-1") == "redhat-1"
    assert flavour("2.15.2") is None and flavour("5.3.30.RELEASE") is None


def test_lines():
    assert major("3.2.12") == 3 and minor_line("3.2.12") == (3, 2) and minor_line("32.0.0-jre") == (32, 0)
    assert minor_line("7") == (7, 0)
