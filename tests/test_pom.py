import pytest
from fakes import fixture_fetch, fixture_fetch_dir, read

from vuln_ticketer.pom import PomError, load_project, parse_pom


def test_simple():
    p = parse_pom(read("simple.xml"), "pom.xml")
    assert p.parent.artifact == "spring-boot-starter-parent" and p.parent.version == "3.2.1"
    text = next(d for d in p.dependencies if d.artifact == "commons-text")
    assert (text.version_raw, text.property, text.version) == ("${commons-text.version}", "commons-text.version", "1.9")
    assert next(d for d in p.dependencies if d.artifact == "spring-boot-starter-web").version is None
    assert [(d.artifact, d.version) for d in p.managed] == [("snakeyaml", "1.33")]
    assert (p.group, p.artifact, p.version) == ("com.acme", "orders-svc", "1.4.0")


def test_project_lookups():
    proj = load_project(fixture_fetch("simple.xml"))
    pom, dep = proj.find_direct("com.google.guava", "guava")
    assert dep.version == "32.0.0-jre"
    assert proj.find_direct(None, "guava")[1].group == "com.google.guava"
    assert proj.find_direct("org.springframework.boot", "spring-boot-starter-web") is None  # no version
    assert proj.find_managed("org.yaml", "snakeyaml")[1].version == "1.33"
    assert proj.find_managed("org.yaml", "nope") is None
    assert proj.property_owner("commons-text.version").path == "pom.xml"
    assert proj.boot() == ("3.2.1", True)
    assert proj.root.path == "pom.xml"


def test_multi_module():
    proj = load_project(fixture_fetch_dir("multi"))
    assert [p.path for p in proj.poms] == ["pom.xml", "api/pom.xml", "app/pom.xml"]
    pom, dep = proj.find_direct("org.apache.poi", "poi")
    assert pom.path == "app/pom.xml" and dep.version == "5.2.2"
    assert proj.property_owner("poi.version").path == "pom.xml"
    assert proj.find_direct("com.acme", "billing-api")[1].version == "2.0.0"  # ${project.version} via parent


def test_nested_pom_path():
    files = {"service/pom.xml": read("multi/pom.xml"), "service/app/pom.xml": read("multi/app/pom.xml")}
    proj = load_project(files.get, "service/pom.xml")
    assert [p.path for p in proj.poms] == ["service/pom.xml", "service/app/pom.xml"]  # missing api module skipped


def test_bom_import():
    assert load_project(fixture_fetch("bom_import.xml")).boot() == ("3.1.5", False)


def test_import_bom_is_not_a_managed_dependency():
    assert load_project(fixture_fetch("bom_import.xml")).find_managed("org.springframework.boot", "spring-boot-dependencies") is None


def test_external_property_unresolved():
    proj = load_project(fixture_fetch("external_prop.xml"))
    pom, dep = proj.find_direct("org.apache.commons", "commons-text")
    assert dep.property == "acme.text.version" and dep.version is None
    assert proj.property_owner("acme.text.version") is None and proj.boot() is None


def test_missing_root():
    assert load_project(lambda path: None) is None


def test_bad_xml():
    with pytest.raises(PomError):
        parse_pom("<project><oops", "pom.xml")
