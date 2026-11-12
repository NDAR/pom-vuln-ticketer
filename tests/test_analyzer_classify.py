import pytest
from fakes import FakeRepo, fixture_fetch, fixture_fetch_dir

from vuln_ticketer.analyzer import classify, select_target
from vuln_ticketer.maven_repo import BootBom
from vuln_ticketer.pom import load_project


@pytest.fixture
def bom():
    return BootBom(FakeRepo())


@pytest.fixture
def simple():
    return load_project(fixture_fetch("simple.xml"))


@pytest.mark.parametrize("installed,fixed,published,exp", [
    ("2.15.2", ["2.15.4"], ["2.15.2", "2.15.3", "2.15.4", "2.16.0"], ("2.15.4", True)),
    ("2.15.2", ["2.14.9", "2.15.4", "2.16.1"], ["2.15.4", "2.16.1"], ("2.15.4", True)),  # same minor preferred
    ("2.15.2", ["2.15.4"], ["2.15.2", "2.15.5"], ("2.15.5", True)),  # not published -> next higher
    ("2.15.2", ["2.15.4"], None, ("2.15.4", False)),  # repository down
    ("2.15.2", ["2.15.4"], [], ("2.15.4", False)),
    ("2.15.2", ["NotAvailable"], ["2.15.4"], (None, False)),
    ("2.15.2", [], ["2.15.4"], (None, False)),
    ("2.15.2", ["3.0.0-RC1"], ["3.0.0-RC1"], (None, False)),
    ("2.15.2", ["2.15.1"], ["2.15.1", "2.15.2"], (None, False)),  # "fix" not above installed
    ("1.9", ["2.0", "1.10.0"], ["1.9", "1.10.0", "2.0"], ("1.10.0", True)),  # same major before lowest overall
    ("32.0.0-jre", ["32.0.1"], ["32.0.0-android", "32.0.0-jre", "32.0.1-android", "32.0.1-jre"], ("32.0.1-jre", True)),
    ("32.0.0-jre", ["32.0.1-android"], ["32.0.1-android", "32.0.1-jre"], ("32.0.1-jre", True)),
])
def test_select_target(installed, fixed, published, exp):
    assert select_target(installed, fixed, published) == exp


def test_direct_literal(simple, bom):
    s = classify("com.google.guava", "guava", "32.0.0-jre", "32.0.1-jre", simple, bom)
    assert (s.kind, s.pom_file, s.section) == ("direct", "pom.xml", "dependencies")
    assert "<version>32.0.1-jre</version>" in s.snippet and "<artifactId>guava</artifactId>" in s.snippet
    assert (s.current, s.target, s.cves, s.verified) == (["32.0.0-jre"], "32.0.1-jre", [], True)


def test_direct_property(simple, bom):
    s = classify("org.apache.commons", "commons-text", "1.9", "1.10.0", simple, bom)
    assert (s.kind, s.section, s.snippet) == ("property", "properties", "<commons-text.version>1.10.0</commons-text.version>")


def test_module_property_points_to_root():
    multi = load_project(fixture_fetch_dir("multi"))
    s = classify("org.apache.poi", "poi", "5.2.2", "5.2.5", multi, None)
    assert (s.kind, s.pom_file) == ("property", "pom.xml")


def test_project_managed(simple, bom):
    s = classify("org.yaml", "snakeyaml", "1.33", "2.0", simple, bom)
    assert (s.kind, s.section) == ("managed", "dependencyManagement") and "<version>2.0</version>" in s.snippet


def test_boot_managed_parent(simple, bom):
    s = classify("com.fasterxml.jackson.core", "jackson-databind", "2.15.3", "2.15.4", simple, bom)
    assert s.kind == "boot" and s.boot_upgrade == "3.2.5" and s.override_property == "jackson-bom.version=2.15.4"
    assert "<version>3.2.5</version>" in s.snippet and "spring-boot-starter-parent" in s.snippet and s.section == "parent"


def test_boot_imported_has_no_override(bom):
    project = load_project(fixture_fetch("bom_import.xml"))
    s = classify("com.fasterxml.jackson.core", "jackson-databind", "2.15.3", "2.15.4", project, bom)
    assert s.kind == "boot" and s.boot_upgrade == "3.2.5" and s.override_property is None
    assert s.section == "dependencyManagement" and "spring-boot-dependencies" in s.snippet and "<scope>import</scope>" in s.snippet


def test_boot_override_only_when_no_boot_release_manages_fix(simple, bom):
    # No 3.x Boot release in the fake repository manages snakeyaml >= 2.4, but the property can be overridden.
    multi = load_project(fixture_fetch_dir("multi"))
    s = classify("org.yaml", "snakeyaml", "2.2", "2.4", multi, bom)
    assert s.kind == "boot" and s.boot_upgrade is None and s.section == "properties"
    assert s.snippet == "<snakeyaml.version>2.4</snakeyaml.version>" and s.override_property is None


def test_transitive_pin(simple, bom):
    s = classify("org.example", "obscure", "1.0", "1.1", simple, bom)
    assert s.kind == "pin" and s.section == "dependencyManagement" and s.pom_file == "pom.xml"
    assert "<artifactId>obscure</artifactId>" in s.snippet and "<version>1.1</version>" in s.snippet
    assert "<dependencyManagement>" in s.snippet and "Transitive" in s.note


def test_unresolvable_property_falls_back_to_pin():
    project = load_project(fixture_fetch("external_prop.xml"))
    s = classify("org.apache.commons", "commons-text", "1.9", "1.10.0", project, None)
    assert s.kind == "pin" and "acme.text.version" in s.note


def test_no_project():
    s = classify("a.b", "c", "1", "2", None, None)
    assert s.kind == "pin" and s.pom_file == "pom.xml"


def test_group_adopted_from_pom(simple, bom):
    assert classify(None, "guava", "32.0.0-jre", "32.0.1-jre", simple, bom).group == "com.google.guava"


def test_group_adopted_from_boot_bom(simple, bom):
    s = classify(None, "jackson-databind", "2.15.3", "2.15.4", simple, bom)
    assert s.group == "com.fasterxml.jackson.core" and s.kind == "boot"


def test_group_unknown(simple, bom):
    s = classify(None, "mystery", "1", "2", simple, bom)
    assert s.kind == "pin" and "<groupId>UNKNOWN</groupId>" in s.snippet and "group" in s.note
