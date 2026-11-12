import dataclasses

import pytest
from fakes import make_deployment, os_finding, java_finding

from vuln_ticketer.models import Report, Suggestion
from vuln_ticketer.ticket import MAX_DESCRIPTION, parse_finding_keys, plan_ticket, render_description, summary_for


def sug(artifact="commons-text", kind="property", cves=(("CVE-1", "CRITICAL"), ("CVE-2", "HIGH")), **over):
    base = dict(group="org.apache.commons", artifact=artifact, current=["1.9"], target="1.10.0", kind=kind,
                pom_file="pom.xml", section="properties", snippet="<commons-text.version>1.10.0</commons-text.version>",
                cves=list(cves), verified=True)
    base.update(over)
    return Suggestion(**base)


def make_report(suggestions=None, no_fix=(), non_pom=(), headline=None, keys=None, pom_missing=False):
    suggestions = [sug()] if suggestions is None else suggestions
    if keys is None:
        keys = [f"{s.group}:{s.artifact}@{s.current[0]}:{c}" for s in suggestions for c, _ in s.cves]
        keys += [f.key for f in list(no_fix) + list(non_pom)]
    return Report(deployment=make_deployment(), suggestions=suggestions, no_fix=list(no_fix), non_pom=list(non_pom),
                  headline=headline, finding_keys=sorted(keys), pom_missing=pom_missing)


EMPTY = make_report(suggestions=[])


def test_summary():
    r = make_report(no_fix=[java_finding(("g", "a"), "1", [], "CVE-3", "HIGH")], non_pom=[os_finding("openssl", "CVE-9", "CRITICAL")])
    assert summary_for(r) == "[orders-svc] Dependency vulnerabilities: 4 findings (2 critical, 2 high)"


def test_context_lines():
    d = render_description(make_report())
    assert d.startswith("*Repository:* orders-svc | *Branch:* main | *Commit:* abc123de | *Pipeline:* orders-pipeline\n")
    assert "*Images:* orders: orders-svc@sha256:aaaaaaaaaaaa\n" in d


def test_description_sections_in_order():
    r = make_report(headline="Upgrading spring-boot-starter-parent 3.2.1 → 3.2.5 resolves 2 of 4 findings.",
                    no_fix=[java_finding(("g", "a"), "1", [], "CVE-3")], non_pom=[os_finding("openssl", "CVE-9")])
    d = render_description(r)
    order = [d.index(x) for x in ("{panel", "h2. Suggested POM changes", "h2. No fix available yet",
                                  "h2. Not fixable in the POM", "{noformat:title=pom-vuln-bot finding keys (do not edit)}")]
    assert order == sorted(order) and "Upgrading spring-boot-starter-parent 3.2.1 → 3.2.5" in d


def test_suggestion_block():
    d = render_description(make_report())
    assert "h3. org.apache.commons:commons-text 1.9 → 1.10.0\n" in d
    assert "File: pom.xml · Section: properties · Version property\n" in d
    assert "* CVE-1 (CRITICAL)\n* CVE-2 (HIGH)\n" in d
    assert "{code:xml}\n<commons-text.version>1.10.0</commons-text.version>\n{code}" in d


@pytest.mark.parametrize("kind,label", [("direct", "Direct dependency"), ("managed", "Project dependencyManagement"),
                                        ("boot", "Managed by Spring Boot"), ("pin", "Transitive pin")])
def test_kind_labels(kind, label):
    assert f"· {label}" in render_description(make_report([sug(kind=kind)]))


def test_unverified_marker():
    d = render_description(make_report([sug(verified=False)]))
    assert "· Version property (not verified against the Maven repository)\n" in d
    assert "not verified" not in render_description(make_report())


def test_override_and_note_lines():
    d = render_description(make_report([sug(kind="boot", override_property="jackson-bom.version=2.15.4", note="Heads up.")]))
    assert "Alternative: set property jackson-bom.version=2.15.4 in <properties>." in d and "Heads up." in d


def test_two_current_versions():
    assert "h3. org.apache.commons:commons-text 1.8, 1.9 → 1.10.0" in render_description(make_report([sug(current=["1.8", "1.9"])]))


def test_empty_sections_omitted():
    d = render_description(make_report())
    assert "No fix available yet" not in d and "Not fixable in the POM" not in d and "{panel" not in d


def test_no_fix_line():
    d = render_description(make_report(no_fix=[java_finding(("com.google.guava", "guava"), "32.0.0-jre", [], "CVE-3", "HIGH")]))
    assert "* com.google.guava:guava 32.0.0-jre — CVE-3 (HIGH)" in d


def test_non_pom_top_five():
    non_pom = [os_finding(f"pkg{i}", f"CVE-{i}", "CRITICAL" if i >= 5 else "HIGH") for i in range(7)]
    d = render_description(make_report(non_pom=non_pom))
    section = d.split("h2. Not fixable in the POM")[1].split("{noformat")[0]
    assert "2 critical, 5 high in non-Java packages (base image or OS)." in section
    bullets = [line for line in section.splitlines() if line.startswith("* ")]
    assert len(bullets) == 5 and "CRITICAL" in bullets[0] and "CRITICAL" in bullets[1] and "HIGH" in bullets[2]


def test_pom_missing_warning():
    d = render_description(make_report(pom_missing=True))
    assert "{warning}pom.xml could not be read at this commit; changes below are generic pins.{warning}" in d


def test_escapes_markup():
    d = render_description(make_report([sug(artifact="we|ird{x}")]))
    assert "h3. org.apache.commons:we\\|ird\\{x\\} 1.9" in d


def test_keys_round_trip():
    r = make_report()
    assert parse_finding_keys(render_description(r)) == set(r.finding_keys)


def test_parse_keys_absent():
    assert parse_finding_keys("someone rewrote this") is None and parse_finding_keys(None) is None


def test_truncation():
    high = [sug(artifact=f"lib-{i:03d}", cves=[(f"CVE-2024-{i:04d}", "HIGH")], snippet="<x>" + "y" * 200 + "</x>") for i in range(300)]
    r = make_report([sug(artifact="critical-lib")] + high)
    d = render_description(r)
    assert len(d) <= MAX_DESCRIPTION and "more suggestions omitted; see AWS Inspector." in d
    assert "{code:xml}" in d and "h3. org.apache.commons:critical-lib" in d  # critical keeps its snippet
    assert "* org.apache.commons:lib-000 1.9 → 1.10.0 (1 CVEs) — properties in pom.xml" in d
    assert parse_finding_keys(d) == set(r.finding_keys)


def test_keys_fall_back_to_digest_when_too_many():
    r = make_report([sug()], keys=[f"com.example.group:artifact-{i}@1.0.0:CVE-2024-{i:05d}" for i in range(900)])
    d = render_description(r)
    keys = parse_finding_keys(d)
    assert len(d) <= MAX_DESCRIPTION and len(keys) == 1 and next(iter(keys)).startswith("sha256:")
    assert plan_ticket(r, d, True).action == "none"


def test_plan_create():
    p = plan_ticket(make_report(), None, False)
    assert p.action == "create" and p.priority_severity == "CRITICAL"
    assert p.summary == "[orders-svc] Dependency vulnerabilities: 2 findings (1 critical, 1 high)"
    assert p.description == render_description(make_report()) and p.comment is None


def test_plan_none_when_clean_and_no_ticket():
    assert plan_ticket(EMPTY, None, False).action == "none"


def test_plan_close():
    p = plan_ticket(EMPTY, render_description(make_report()), True)
    assert p.action == "close"
    assert p.comment == "All critical and high findings resolved as of abc123de (pipeline orders-pipeline)."


def test_plan_unchanged():
    r = make_report()
    assert plan_ticket(r, render_description(r), True).action == "none"


def test_plan_update_diff():
    old = make_report(keys=[f"k{i}" for i in range(8)])  # k0..k7
    new = make_report(keys=[f"k{i}" for i in range(2, 9)])  # k2..k8: 2 resolved, 1 new, 6 unchanged
    p = plan_ticket(new, render_description(old), True)
    assert p.action == "update" and p.description == render_description(new)
    assert p.comment.startswith("Deploy abc123de via orders-pipeline: 2 resolved, 1 new, 6 unchanged\n")
    assert "New:\n* k8\n" in p.comment and "Resolved:\n* k0\n* k1" in p.comment


def test_plan_update_caps_key_lists():
    new = make_report(keys=[f"k{i:02d}" for i in range(30)])
    p = plan_ticket(new, render_description(make_report(keys=["old"])), True)
    assert p.comment.count("\n* k") == 20 and "…and 10 more" in p.comment


def test_plan_update_human_edited():
    p = plan_ticket(make_report(), "someone rewrote this", True)
    assert p.action == "update"
    assert p.comment == ("Deploy abc123de via orders-pipeline: previous ticket state could not be read; "
                         "description regenerated.")


def test_priority_high_only():
    assert plan_ticket(make_report([sug(cves=[("CVE-2", "HIGH")])]), None, False).priority_severity == "HIGH"
