# pom-vuln-ticketer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After each successful CodePipeline deployment to ECS, create or refresh one JIRA ticket per CodeCommit repo listing the CRITICAL/HIGH Inspector findings on the deployed image with the exact `pom.xml` change that fixes each.

**Architecture:** An EventBridge rule on pipeline success starts a Step Functions workflow of four Python Lambdas: resolve the deployment (repo, commit, image digests), wait for the Inspector scan, analyze findings against the POM (rule-based, verified against a Maven repository), and publish to JIRA Data Center from inside the VPC. All state lives in the JIRA ticket itself; the only storage is an S3 bucket that carries the report between the last two steps.

**Tech Stack:** Python 3.12, AWS SAM, Step Functions, boto3, `requests`; tests with pytest, `botocore.stub`, `responses`.

**Spec:** `docs/superpowers/specs/2026-11-11-pom-vuln-ticketer-design.md` — read it before starting any task.

## Global Constraints

- Only findings with severity `CRITICAL` or `HIGH` exist for this tool. The filter is fixed in code, not configurable.
- No LLM calls. No writes to CodeCommit. No Maven execution.
- Never suggest a pre-release version (RC, milestone, alpha/beta, SNAPSHOT).
- Every suggested version is verified against the Maven repository, or the suggestion is marked `not verified`.
- JIRA labels are exactly `pom-vuln-bot` and `repo-<repo>`. JIRA API is Data Center REST v2 (`/rest/api/2`) with `Authorization: Bearer <PAT>`. Descriptions use JIRA wiki markup.
- JIRA description limit: 32,767 characters.
- Only the PublishJira function is attached to the VPC; it has reserved concurrency 1.
- Python 3.12, arm64, layout and conventions as in `../codecommit-pr` (`src/<package>/`, `pyproject.toml` with `pythonpath = ["src"]`, structured JSON logs).
- Runtime dependencies: `requests` only (boto3 comes from the Lambda runtime). XML is parsed with the standard library.
- Commit after every task; end commit messages with `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>`.
- Run tests with `.venv/bin/pytest -q`.

## Review Focus

Inputs the spec implies but does not spell out. Each has a test in the task named.

1. **Flavoured versions** (`guava 32.0.0-jre`, `-android`, `.redhat-1`): the target must keep the installed flavour (`32.1.3-jre`, never `32.1.3-android`), and such qualifiers are not pre-releases. → Tasks 3, 6
2. **Same artifact at two versions in one image** (duplicate or shaded jars): one suggestion, current version shown as both, target covers the highest requirement. → Task 7
3. **Version property not defined in the repo** (`${x}` inherited from an external company parent): no crash; fall back to a `dependencyManagement` pin. → Tasks 4, 6
4. **Human-edited ticket** (finding-key block deleted or mangled): treated as "changed"; description rewritten; change comment says the previous state was unreadable. → Task 10
5. **More than one page of results** from Inspector, CodePipeline action executions, or JIRA: all pages are read. → Tasks 8, 9

## File Structure

```
template.yaml                    SAM: functions, state machine, rule, bucket, alarm
statemachine/workflow.asl.json   Step Functions definition
pyproject.toml, requirements-dev.txt, .gitignore, README.md
src/requirements.txt             requests
src/vuln_ticketer/
  models.py       dataclasses shared by all modules (+ dict round-trip)
  versions.py     Maven version ordering, pre-release and flavour helpers
  pom.py          POM parsing, property resolution, multi-module Project
  maven_repo.py   repository client and Spring Boot BOM resolution
  analyzer.py     target selection, classification, roll-up → Report
  inspector.py    scan readiness and findings → Finding objects
  deployment.py   pipeline execution → Deployment
  ticket.py       render description, finding keys, diff → TicketPlan
  jira.py         JIRA REST client
  config.py       environment settings and SSM config
  handlers.py     four Lambda entry points
  log.py          JSON logger
scripts/probe_inspector.py       capture real Inspector records as fixtures
scripts/replay.py                run the flow for one pipeline execution
tests/                           one test file per module; fixtures in tests/fixtures/
```

Two deviations from the spec's layout, both deliberate: version comparison lives in its own `versions.py` (the spec placed it in `maven_repo.py`), and the report always travels through S3 (the spec said "only when large"), which removes a branch.

---

### Task 1: Scaffold and Inspector probe

**Files:**
- Create: `pyproject.toml`, `requirements-dev.txt`, `src/requirements.txt`, `.gitignore`, `src/vuln_ticketer/__init__.py`, `src/vuln_ticketer/log.py`, `scripts/probe_inspector.py`, `tests/fixtures/inspector_finding_java.json`, `tests/fixtures/inspector_finding_os.json`, `tests/fixtures/inspector_coverage.json`, `tests/test_log.py`

**Interfaces:**
- Produces: `log.get_logger(name: str) -> logging.Logger` emitting one JSON object per line with keys `level`, `message`, plus any `extra` fields; fixtures used by Task 8.

- [ ] **Step 1: Create scaffold.** `pyproject.toml` identical to `../codecommit-pr/pyproject.toml`. `requirements-dev.txt`: `boto3`, `requests`, `responses`, `pytest`. `src/requirements.txt`: `requests`. `.gitignore` copied from `../codecommit-pr/.gitignore`. Create the venv: `python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`.

- [ ] **Step 2: Write failing test `tests/test_log.py`**

```python
def test_logger_emits_json(capsys):
    from vuln_ticketer.log import get_logger
    get_logger("t").info("hello", extra={"executionId": "abc"})
    rec = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rec["level"] == "INFO" and rec["message"] == "hello" and rec["executionId"] == "abc"
```

- [ ] **Step 3: Run** `.venv/bin/pytest tests/test_log.py -q` → FAIL (module missing). Implement `log.py` (stdout handler, JSON formatter; port from `../codecommit-pr/src/pr_reviewer/log.py` if it fits). Run → PASS.

- [ ] **Step 4: Write `scripts/probe_inspector.py`.** CLI: `probe_inspector.py <ecr-repo> <image-digest> [--region R]`. It calls `inspector2.list_coverage` (filter `ecrRepositoryName` EQUALS) and `inspector2.list_findings` (filter `ecrImageHash` EQUALS, `findingStatus` ACTIVE) and prints: the coverage record for the digest; one finding whose `vulnerablePackages[0].packageManager` is a Java manager; one that is not. Output is JSON with account IDs replaced by `111111111111`.

- [ ] **Step 5: Capture real fixtures.** Run `aws sts get-caller-identity`. If it fails, or you do not know an ECR repo/digest of a deployed Spring Boot image, **stop and ask your human partner** for credentials and one repo + digest. Then run the probe and save the three records into the fixture files named above.

- [ ] **Step 6: Record what the probe showed** at the top of `tests/fixtures/README.md`, answering exactly: (a) the format of `vulnerablePackages[].name` for a jar (is the group included, and with which separator?); (b) the `packageManager` values seen; (c) the format of `fixedInVersion` (single value, list, `NotAvailable`); (d) the `scanStatus.statusCode` and `scanStatus.reason` of a completed scan. Tasks 8 assumes: name is `group:artifact`, Java managers are `{"JAR","POM","GRADLE","POMPROPERTIES"}`, ready is `statusCode == "ACTIVE" and reason == "SUCCESSFUL"`. If the probe contradicts any of these, note it in the README; Task 8 follows the README.

- [ ] **Step 7: Commit** `chore: scaffold project and capture Inspector fixtures`.

---

### Task 2: Shared models

**Files:**
- Create: `src/vuln_ticketer/models.py`, `tests/test_models.py`

**Interfaces — Produces** (all `@dataclass`, all fields keyword-constructible):

```python
Image(service: str, ecr_repo: str, digest: str, uri: str)
Deployment(repo: str, branch: str, commit: str, pipeline: str, execution_id: str, images: list[Image])
Finding(group: str | None, artifact: str, version: str, fixed_versions: list[str],
        cve: str, severity: str, title: str, is_java: bool, file_path: str,
        services: list[str])
    .key -> str            # f"{group or '?'}:{artifact}@{version}:{cve}"
Suggestion(group: str | None, artifact: str, current: list[str], target: str,
           kind: str,       # "direct" | "property" | "managed" | "boot" | "pin"
           pom_file: str, section: str, snippet: str,
           cves: list[tuple[str, str]],      # (cve, severity), CRITICAL first
           verified: bool, boot_upgrade: str | None = None,
           override_property: str | None = None, note: str | None = None)
Report(deployment: Deployment, suggestions: list[Suggestion], no_fix: list[Finding],
       non_pom: list[Finding], headline: str | None, finding_keys: list[str],
       pom_missing: bool)
    .to_dict() -> dict ; Report.from_dict(d: dict) -> Report     # JSON-safe round trip
    .counts() -> dict[str, int]   # {"total", "critical", "high"} over suggestions' cves + no_fix + non_pom
Deployment.to_dict() / Deployment.from_dict()
TicketPlan(action: str,     # "create" | "update" | "close" | "none"
           summary: str = "", description: str = "", comment: str | None = None,
           priority_severity: str | None = None)   # "CRITICAL" | "HIGH"
```

- [ ] **Step 1: Write failing tests**

```python
def test_finding_key():
    f = Finding(group="com.fasterxml.jackson.core", artifact="jackson-databind", version="2.15.2",
                fixed_versions=["2.15.4"], cve="CVE-2023-1", severity="HIGH", title="t",
                is_java=True, file_path="app.jar/BOOT-INF/lib/jackson-databind-2.15.2.jar", services=["svc"])
    assert f.key == "com.fasterxml.jackson.core:jackson-databind@2.15.2:CVE-2023-1"
    assert dataclasses.replace(f, group=None).key == "?:jackson-databind@2.15.2:CVE-2023-1"

def test_report_round_trip():   # build a Report with one of everything
    assert Report.from_dict(json.loads(json.dumps(report.to_dict()))) == report

def test_counts():              # 1 suggestion with cves [("A","CRITICAL"),("B","HIGH")], 1 no_fix HIGH, 1 non_pom CRITICAL
    assert report.counts() == {"total": 4, "critical": 2, "high": 2}
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: shared models`.

---

### Task 3: Maven version ordering

**Files:**
- Create: `src/vuln_ticketer/versions.py`, `tests/test_versions.py`

**Interfaces — Produces:**

```python
compare(a: str, b: str) -> int            # -1, 0, 1 — Maven ComparableVersion ordering
sort_versions(vs: Iterable[str]) -> list[str]   # ascending
is_prerelease(v: str) -> bool
flavour(v: str) -> str | None             # trailing non-ordering qualifier: "jre", "android", "redhat-1"; else None
major(v: str) -> int ; minor_line(v: str) -> tuple[int, int]
```

Rules: split on `.` and `-` and at digit/letter boundaries; numeric segments compare numerically; trailing zeros are insignificant (`1.0 == 1.0.0`); qualifier order `alpha|a < beta|b < milestone|m < rc|cr < snapshot < "" = ga = final = release < sp`; unknown qualifiers sort after release, alphabetically. `is_prerelease` is true for alpha/beta/milestone/rc/cr/snapshot qualifiers (`a`, `b`, `m` only when followed by a digit). `flavour` returns the unknown-qualifier tail.

- [ ] **Step 1: Write failing tests**

```python
@pytest.mark.parametrize("a,b,exp", [
    ("2.15.2", "2.15.4", -1), ("2.9", "2.10", -1), ("1.0", "1.0.0", 0),
    ("3.2.0-RC1", "3.2.0", -1), ("3.2.0-M1", "3.2.0-RC1", -1), ("3.2.0-SNAPSHOT", "3.2.0", -1),
    ("5.3.30.RELEASE", "5.3.30", 0), ("2.7.18", "3.0.0", -1), ("1.2.3.Final", "1.2.4.Final", -1),
    ("32.0.0-jre", "32.1.3-jre", -1), ("1.0-sp1", "1.0", 1),
])
def test_compare(a, b, exp): assert compare(a, b) == exp and compare(b, a) == -exp

def test_sort(): assert sort_versions(["2.10", "2.9", "2.9.1"]) == ["2.9", "2.9.1", "2.10"]

@pytest.mark.parametrize("v,exp", [("3.2.0-RC1", True), ("3.2.0-M2", True), ("1.0-SNAPSHOT", True),
    ("2.0.0-alpha1", True), ("2.0.0-beta", True), ("3.2.0", False), ("5.3.30.RELEASE", False),
    ("32.0.0-jre", False), ("32.0.0-android", False), ("1.2.3.Final", False), ("2.1.0.redhat-1", False)])
def test_is_prerelease(v, exp): assert is_prerelease(v) is exp

def test_flavour():
    assert flavour("32.0.0-jre") == "jre" and flavour("32.0.0-android") == "android"
    assert flavour("2.15.2") is None and flavour("5.3.30.RELEASE") is None

def test_lines(): assert major("3.2.12") == 3 and minor_line("3.2.12") == (3, 2) and minor_line("32.0.0-jre") == (32, 0)
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: Maven version ordering`.

---

### Task 4: POM parsing

**Files:**
- Create: `src/vuln_ticketer/pom.py`, `tests/test_pom.py`, fixtures `tests/fixtures/poms/{simple,multi/pom,multi/api/pom,multi/app/pom,bom_import,external_prop}.xml`

**Interfaces — Produces:**

```python
Dep(group: str, artifact: str, version_raw: str | None, version: str | None,
    property: str | None, scope: str | None, type: str | None)
    # version_raw "${jackson.version}" → property "jackson.version", version = resolved value or None
Pom(path: str, group: str | None, artifact: str, version: str | None, parent: Dep | None,
    properties: dict[str, str], dependencies: list[Dep], managed: list[Dep], modules: list[str])
parse_pom(xml_text: str, path: str) -> Pom         # raises PomError on unparseable XML
load_project(fetch: Callable[[str], str | None], pom_path: str = "pom.xml") -> Project | None
    # fetch(path) returns file text or None; None for the root → returns None
Project.poms: list[Pom]; Project.root: Pom
Project.find_direct(group: str | None, artifact: str) -> tuple[Pom, Dep] | None    # in <dependencies> with a <version>
Project.find_managed(group: str | None, artifact: str) -> tuple[Pom, Dep] | None   # in <dependencyManagement>, not scope=import
Project.property_owner(name: str) -> Pom | None     # the POM whose <properties> defines it
Project.boot() -> tuple[str, bool] | None           # (boot version, is_parent)
```

Decisions: XML namespace is stripped before lookup. Properties resolve through the module's own properties, then the root's; `${project.version}` resolves to the POM's version (falling back to its parent's). `group=None` in a lookup matches on artifact alone. `load_project` follows `<modules>` recursively relative to each POM's directory; a module whose POM is missing is skipped. `boot()` looks at the root: parent `org.springframework.boot:spring-boot-starter-parent` → `(version, True)`; else an import-scoped `org.springframework.boot:spring-boot-dependencies` in `managed` → `(version, False)`; else `None`.

Fixtures: `simple.xml` — parent `spring-boot-starter-parent 3.2.1`; properties `commons-text.version=1.9`; dependencies `spring-boot-starter-web` (no version), `org.apache.commons:commons-text ${commons-text.version}`, `com.google.guava:guava 32.0.0-jre`; dependencyManagement `org.yaml:snakeyaml 1.33`. `multi/` — root with modules `api`, `app`, property `poi.version=5.2.2`; `app` declares `org.apache.poi:poi ${poi.version}`. `bom_import.xml` — no parent; imports `spring-boot-dependencies 3.1.5` (type pom, scope import). `external_prop.xml` — parent `com.acme:acme-parent 7`; dependency `org.apache.commons:commons-text ${acme.text.version}` with no such property defined.

- [ ] **Step 1: Write failing tests**

```python
def test_simple():
    p = parse_pom(read("simple.xml"), "pom.xml")
    assert p.parent.artifact == "spring-boot-starter-parent" and p.parent.version == "3.2.1"
    text = next(d for d in p.dependencies if d.artifact == "commons-text")
    assert (text.version_raw, text.property, text.version) == ("${commons-text.version}", "commons-text.version", "1.9")
    assert next(d for d in p.dependencies if d.artifact == "spring-boot-starter-web").version is None
    assert [(d.artifact, d.version) for d in p.managed] == [("snakeyaml", "1.33")]

def test_project_lookups():
    proj = load_project(fixture_fetch("simple.xml"))
    pom, dep = proj.find_direct("com.google.guava", "guava"); assert dep.version == "32.0.0-jre"
    assert proj.find_direct(None, "guava")[1].group == "com.google.guava"
    assert proj.find_direct("org.springframework.boot", "spring-boot-starter-web") is None   # no version
    assert proj.find_managed("org.yaml", "snakeyaml")[1].version == "1.33"
    assert proj.property_owner("commons-text.version").path == "pom.xml"
    assert proj.boot() == ("3.2.1", True)

def test_multi_module():
    proj = load_project(fixture_fetch_dir("multi"))
    assert [p.path for p in proj.poms] == ["pom.xml", "api/pom.xml", "app/pom.xml"]
    pom, dep = proj.find_direct("org.apache.poi", "poi")
    assert pom.path == "app/pom.xml" and dep.version == "5.2.2" and proj.property_owner("poi.version").path == "pom.xml"

def test_bom_import(): assert load_project(fixture_fetch("bom_import.xml")).boot() == ("3.1.5", False)

def test_external_property_unresolved():           # Review Focus 3
    proj = load_project(fixture_fetch("external_prop.xml"))
    pom, dep = proj.find_direct("org.apache.commons", "commons-text")
    assert dep.property == "acme.text.version" and dep.version is None
    assert proj.property_owner("acme.text.version") is None and proj.boot() is None

def test_missing_root(): assert load_project(lambda path: None) is None
def test_bad_xml():
    with pytest.raises(PomError): parse_pom("<project><oops", "pom.xml")
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: POM parsing and project model`.

---

### Task 5: Maven repository client and Boot BOM

**Files:**
- Create: `src/vuln_ticketer/maven_repo.py`, `tests/test_maven_repo.py`, fixtures under `tests/fixtures/maven/` (trimmed real files: `spring-boot-dependencies-3.2.1.pom`, `-3.2.5.pom`, `-3.2.12.pom`, `jackson-bom-2.15.3.pom`, `jackson-bom-2.15.4.pom`, `jackson-bom-2.17.2.pom`, and `maven-metadata.xml` for `spring-boot-dependencies` and `jackson-databind`)

**Interfaces:**
- Consumes: `versions.sort_versions`, `versions.is_prerelease`, `versions.compare`, `versions.minor_line`, `versions.major`; `pom.parse_pom`.
- Produces:

```python
class MavenRepoUnavailable(Exception)
class MavenRepo:
    def __init__(self, base_url: str = "https://repo1.maven.org/maven2", session: requests.Session | None = None, timeout: float = 10)
    def versions(self, group: str, artifact: str) -> list[str]       # ascending, pre-releases removed; [] on 404
    def fetch_pom(self, group: str, artifact: str, version: str) -> str | None   # None on 404
    # network error / 5xx → MavenRepoUnavailable. Results cached per instance.

ManagedEntry(version: str, property: str | None, bom: tuple[str, str] | None)
    # property: the Boot-level property that sets this version ("jackson-bom.version", "snakeyaml.version")
    # bom: (group, artifact) of the nested BOM that supplied the entry, else None
class BootBom:
    def __init__(self, repo: MavenRepo)
    def managed(self, boot_version: str) -> dict[tuple[str, str], ManagedEntry]
    def lowest_boot_managing(self, group: str, artifact: str, target: str, current_boot: str) -> str | None
    def override_value(self, entry: ManagedEntry, group: str, artifact: str, target: str) -> str | None
```

Decisions:
- `managed()` parses `org.springframework.boot:spring-boot-dependencies:<v>`: each `dependencyManagement` entry resolved through that POM's properties; entries with `scope=import` are fetched and their managed entries merged in (nested one level deeper at most, i.e. depth 2), carrying the Boot-level property and `bom`. Entries declared directly in Boot's POM win over nested ones.
- `lowest_boot_managing()` candidates: published Boot versions `>` `current_boot` with the same major, ordered same-minor-line first (ascending), then higher minors (ascending). Return the first whose managed version of the artifact is `>= target`. Stop after 25 BOM fetches and return `None`.
- `override_value()`: entry without `property` → `None`. Entry with `bom is None` → `target`. Entry with a nested BOM → the lowest published BOM version `>= target` (same minor line preferred) whose own managed version of the artifact is `>= target`, checking at most 3 BOM versions; else `None`.

Fixture content (trim real POMs to these entries): Boot 3.2.1 → `jackson-bom.version=2.15.3`, `snakeyaml.version=2.2`, direct entry `org.yaml:snakeyaml ${snakeyaml.version}`, import `com.fasterxml.jackson:jackson-bom ${jackson-bom.version}`. Boot 3.2.5 → `jackson-bom.version=2.15.4`. Boot 3.2.12 → `jackson-bom.version=2.15.4`. Boot metadata lists `3.1.5, 3.2.0-RC1, 3.2.1, 3.2.5, 3.2.12, 3.3.0, 4.0.0`; Boot 3.3.0 → `jackson-bom.version=2.17.2` (add a fixture POM). Each jackson-bom manages `com.fasterxml.jackson.core:jackson-databind` at the BOM's own version.

- [ ] **Step 1: Write failing tests** (HTTP stubbed with `responses`)

```python
def test_versions_sorted_no_prerelease():
    assert repo.versions("org.springframework.boot", "spring-boot-dependencies") == ["3.1.5", "3.2.1", "3.2.5", "3.2.12", "3.3.0", "4.0.0"]
def test_versions_404_is_empty(): assert repo.versions("x", "nope") == []
def test_unavailable():           # 503, and requests.ConnectionError
    with pytest.raises(MavenRepoUnavailable): repo.versions("org.x", "y")
def test_cache(): repo.versions(g, a); repo.versions(g, a); assert len(responses.calls) == 1
def test_custom_base_url(): MavenRepo("https://nexus.corp/repo/").versions(g, a); assert responses.calls[0].request.url.startswith("https://nexus.corp/repo/org/")

def test_managed_direct_and_nested():
    m = BootBom(repo).managed("3.2.1")
    assert m[("org.yaml", "snakeyaml")] == ManagedEntry("2.2", "snakeyaml.version", None)
    assert m[("com.fasterxml.jackson.core", "jackson-databind")] == ManagedEntry("2.15.3", "jackson-bom.version", ("com.fasterxml.jackson", "jackson-bom"))
def test_lowest_boot_same_minor():
    assert bom.lowest_boot_managing("com.fasterxml.jackson.core", "jackson-databind", "2.15.4", "3.2.1") == "3.2.5"
def test_lowest_boot_next_minor():
    assert bom.lowest_boot_managing("com.fasterxml.jackson.core", "jackson-databind", "2.16.0", "3.2.1") == "3.3.0"
def test_lowest_boot_none_in_major():
    assert bom.lowest_boot_managing("com.fasterxml.jackson.core", "jackson-databind", "2.99.0", "3.2.1") is None   # never 4.0.0
def test_override_direct(): assert bom.override_value(m[("org.yaml", "snakeyaml")], "org.yaml", "snakeyaml", "2.3") == "2.3"
def test_override_nested_bom():
    assert bom.override_value(m[jackson_key], "com.fasterxml.jackson.core", "jackson-databind", "2.15.4") == "2.15.4"   # jackson-bom 2.15.4
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: Maven repository client and Boot BOM resolution`.

---

### Task 6: Analyzer — target selection and classification

**Files:**
- Create: `src/vuln_ticketer/analyzer.py`, `tests/test_analyzer_classify.py`, `tests/fakes.py`

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces:

```python
select_target(installed: str, fixed: list[str], published: list[str] | None) -> tuple[str | None, bool]
    # (target, verified). published=None means the repository was unavailable.
classify(group: str | None, artifact: str, installed: str, target: str,
         project: Project | None, boot_bom: BootBom | None) -> Suggestion
    # returns a Suggestion with current=[installed], cves=[], verified=True (caller fills cves/verified)
tests/fakes.py: FakeRepo (versions/fetch_pom from dicts; `down=True` raises MavenRepoUnavailable)
```

`select_target` rules: drop candidates that are `<= installed`, pre-release, or empty/`NotAvailable`; none left → `(None, False)`. Prefer a candidate in the installed minor line, then the installed major, then the lowest overall. If `published is None` → `(candidate, False)`. Otherwise the target is the lowest published version `>= candidate` **with the same flavour as `installed`** and in the candidate's major line; if none is published → `(candidate, False)`.

`classify` rules (first match wins) and exact output:

| Case | Condition | `kind` | `pom_file` | `section` | `snippet` |
|---|---|---|---|---|---|
| 1a | `find_direct` hit, literal version | `direct` | that POM's path | `dependencies` | the full `<dependency>` element with the new version |
| 1b | `find_direct` hit via property that `property_owner` finds | `property` | owner POM's path | `properties` | `<name>target</name>` |
| 2 | `find_managed` hit | `managed` (or `property`, as 1b) | that POM's path | `dependencyManagement` | the `<dependency>` element |
| 3 | `project.boot()` and Boot's `managed()` contains the artifact, and `lowest_boot_managing` or `override_value` gives a result | `boot` | root path | `parent` (or `dependencyManagement` when Boot is imported) | the `<parent>` block (or the BOM `<dependency>`) with the new Boot version; `boot_upgrade` = that version; `override_property` = `"<prop>=<value>"` only when Boot is the parent and `override_value` is not `None` |
| 4 | anything else, including `project is None`, an unresolvable property, or a group that is unknown | `pin` | root path (`pom.xml` when no project) | `dependencyManagement` | a `<dependencyManagement><dependencies><dependency>` block pinning `target` |

In case 3 with only an override available (no Boot version found), `boot_upgrade` is `None` and the snippet is the property line in `properties`. In case 4 set `note`: `"Transitive dependency; pinned via dependencyManagement."`; when the property was unresolvable, `"Version comes from ${<prop>}, which is not defined in this repository; pin shown instead."`; when `group is None`, the snippet uses `<groupId>UNKNOWN</groupId>` and the note says the group could not be determined. When `group is None` and the POM or Boot BOM has exactly one entry with that artifact ID, adopt its group.

- [ ] **Step 1: Write failing tests** (project from Task 4 fixtures; `BootBom(FakeRepo(...))` loaded with Task 5 fixtures)

```python
@pytest.mark.parametrize("installed,fixed,published,exp", [
    ("2.15.2", ["2.15.4"], ["2.15.2", "2.15.3", "2.15.4", "2.16.0"], ("2.15.4", True)),
    ("2.15.2", ["2.14.9", "2.15.4", "2.16.1"], ["2.15.4", "2.16.1"], ("2.15.4", True)),   # same minor preferred
    ("2.15.2", ["2.15.4"], ["2.15.2", "2.15.5"], ("2.15.5", True)),                          # not published → next higher
    ("2.15.2", ["2.15.4"], None, ("2.15.4", False)),                                         # repo down
    ("2.15.2", ["2.15.4"], [], ("2.15.4", False)),
    ("2.15.2", ["NotAvailable"], ["2.15.4"], (None, False)),
    ("2.15.2", [], ["2.15.4"], (None, False)),
    ("2.15.2", ["3.0.0-RC1"], ["3.0.0-RC1"], (None, False)),
    ("32.0.0-jre", ["32.0.1"], ["32.0.0-android", "32.0.0-jre", "32.0.1-android", "32.0.1-jre"], ("32.0.1-jre", True)),  # Review Focus 1
])
def test_select_target(installed, fixed, published, exp): assert select_target(installed, fixed, published) == exp

def test_direct_literal():
    s = classify("com.google.guava", "guava", "32.0.0-jre", "32.0.1-jre", simple, bom)
    assert (s.kind, s.pom_file, s.section) == ("direct", "pom.xml", "dependencies") and "<version>32.0.1-jre</version>" in s.snippet
def test_direct_property():
    s = classify("org.apache.commons", "commons-text", "1.9", "1.10.0", simple, bom)
    assert (s.kind, s.section, s.snippet) == ("property", "properties", "<commons-text.version>1.10.0</commons-text.version>")
def test_module_property_points_to_root():
    s = classify("org.apache.poi", "poi", "5.2.2", "5.2.5", multi, None); assert (s.kind, s.pom_file) == ("property", "pom.xml")
def test_project_managed():
    s = classify("org.yaml", "snakeyaml", "1.33", "2.0", simple, bom); assert (s.kind, s.section) == ("managed", "dependencyManagement")
def test_boot_managed_parent():
    s = classify("com.fasterxml.jackson.core", "jackson-databind", "2.15.3", "2.15.4", simple, bom)
    assert s.kind == "boot" and s.boot_upgrade == "3.2.5" and s.override_property == "jackson-bom.version=2.15.4"
    assert "<version>3.2.5</version>" in s.snippet and s.section == "parent"
def test_boot_imported_has_no_override():
    s = classify("com.fasterxml.jackson.core", "jackson-databind", "2.15.3", "2.15.4", bom_import_project, bom)
    assert s.kind == "boot" and s.override_property is None and s.section == "dependencyManagement"
def test_transitive_pin():
    s = classify("org.example", "obscure", "1.0", "1.1", simple, bom)
    assert s.kind == "pin" and "<artifactId>obscure</artifactId>" in s.snippet and "<version>1.1</version>" in s.snippet and "Transitive" in s.note
def test_unresolvable_property_falls_back_to_pin():      # Review Focus 3
    s = classify("org.apache.commons", "commons-text", "1.9", "1.10.0", external_prop, None)
    assert s.kind == "pin" and "acme.text.version" in s.note
def test_no_project(): assert classify("a.b", "c", "1", "2", None, None).kind == "pin"
def test_group_adopted_from_pom(): assert classify(None, "guava", "32.0.0-jre", "32.0.1-jre", simple, bom).group == "com.google.guava"
def test_group_unknown(): assert "UNKNOWN" in classify(None, "mystery", "1", "2", simple, bom).snippet
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: target selection and POM classification`.

---

### Task 7: Analyzer — roll-up and report

**Files:**
- Modify: `src/vuln_ticketer/analyzer.py`
- Create: `tests/test_analyzer_report.py`

**Interfaces:**
- Consumes: `select_target`, `classify`, `MavenRepo`, `BootBom`, models.
- Produces: `analyze(deployment: Deployment, findings: list[Finding], project: Project | None, repo: MavenRepo) -> Report`

Rules:
- Non-Java findings → `non_pom`. Java findings are grouped by `(group, artifact)`.
- Per group: each finding's target is computed with `select_target` (published versions fetched once per artifact; `MavenRepoUnavailable` anywhere → treat the repository as down for the whole run: `published=None`, `boot_bom=None`). Findings with no target → `no_fix`. The group's target is the highest target among its findings; `current` is the sorted distinct installed versions; `cves` sorted CRITICAL first then by CVE ID; `verified` is the AND of the findings' flags.
- `classify` is called once per group with the lowest installed version.
- Headline: if two or more suggestions have `kind == "boot"` with a `boot_upgrade`, the headline version is the highest of them, every such suggestion's `boot_upgrade` and snippet are aligned to it, and `headline` is exactly `"Upgrading spring-boot-starter-parent {old} → {new} resolves {n} of {total} findings."` where `n` counts the CVEs under those suggestions and `total` is the count of all findings. (For an imported BOM the name is `spring-boot-dependencies`.) Otherwise `None`.
- Suggestions are ordered: `boot` first, then by highest severity, then artifact name. `finding_keys` = sorted keys of all findings. `pom_missing = project is None`.

- [ ] **Step 1: Write failing tests**

```python
def test_merges_same_artifact():
    r = analyze(dep, [f(databind, "2.15.3", ["2.15.4"], "CVE-1", "HIGH"), f(databind, "2.15.3", ["2.15.4"], "CVE-2", "CRITICAL")], simple, repo)
    assert len(r.suggestions) == 1 and r.suggestions[0].cves == [("CVE-2", "CRITICAL"), ("CVE-1", "HIGH")]
def test_two_installed_versions():                       # Review Focus 2
    r = analyze(dep, [f(guava, "31.1-jre", ["32.0.1"], "CVE-1", "HIGH"), f(guava, "32.0.0-jre", ["32.0.1"], "CVE-1", "HIGH")], simple, repo)
    assert len(r.suggestions) == 1 and r.suggestions[0].current == ["31.1-jre", "32.0.0-jre"] and r.suggestions[0].target == "32.0.1-jre"
def test_no_fix_and_non_pom():
    r = analyze(dep, [f(guava, "32.0.0-jre", ["NotAvailable"], "CVE-1", "HIGH"), os_finding("openssl", "CVE-9", "CRITICAL")], simple, repo)
    assert r.suggestions == [] and [x.cve for x in r.no_fix] == ["CVE-1"] and [x.cve for x in r.non_pom] == ["CVE-9"]
def test_headline():
    r = analyze(dep, [f(databind, "2.15.3", ["2.15.4"], "CVE-1", "HIGH"), f(snakeyaml_boot_managed, ...), f(guava, ...)], project_without_own_snakeyaml, repo)
    assert r.headline == "Upgrading spring-boot-starter-parent 3.2.1 → 3.2.5 resolves 2 of 3 findings."
    assert [s.kind for s in r.suggestions][:2] == ["boot", "boot"] and {s.boot_upgrade for s in r.suggestions[:2]} == {"3.2.5"}
def test_single_boot_suggestion_has_no_headline(): assert analyze(dep, [f(databind, "2.15.3", ["2.15.4"], "CVE-1", "HIGH")], simple, repo).headline is None
def test_repo_down():
    r = analyze(dep, [f(databind, "2.15.3", ["2.15.4"], "CVE-1", "HIGH")], simple, FakeRepo(down=True))
    assert r.suggestions[0].verified is False and r.suggestions[0].kind == "pin" and r.headline is None
def test_pom_missing(): r = analyze(dep, [f(guava, "32.0.0-jre", ["32.0.1"], "CVE-1", "HIGH")], None, repo); assert r.pom_missing and r.suggestions[0].kind == "pin"
def test_empty(): r = analyze(dep, [], simple, repo); assert r.suggestions == [] and r.finding_keys == [] and r.counts()["total"] == 0
def test_finding_keys_sorted(): assert r.finding_keys == sorted(x.key for x in findings)
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: analyzer roll-up and report`.

---

### Task 8: Inspector gateway

**Files:**
- Create: `src/vuln_ticketer/inspector.py`, `tests/test_inspector.py`

**Interfaces:**
- Consumes: `Image`, `Finding`; fixtures and `tests/fixtures/README.md` from Task 1 (the README overrides the assumptions below where it differs).
- Produces:

```python
JAVA_MANAGERS = {"JAR", "POM", "GRADLE", "POMPROPERTIES"}
scan_ready(client, images: list[Image]) -> bool
list_findings(client, images: list[Image]) -> list[Finding]
```

Decisions:
- `scan_ready`: for each image, paginate `list_coverage` with `filterCriteria={"ecrRepositoryName": [{"comparison": "EQUALS", "value": ecr_repo}]}`; the image is ready when a record whose `resourceId` ends with the digest has `scanStatus.statusCode == "ACTIVE"` and `scanStatus.reason == "SUCCESSFUL"`. No record → not ready. All images must be ready. Empty `images` → `True`.
- `list_findings`: per image, paginate `list_findings` with filter `ecrImageHash` EQUALS digest, `findingStatus` EQUALS `ACTIVE`, `findingType` EQUALS `PACKAGE_VULNERABILITY`, `severity` EQUALS `CRITICAL` and EQUALS `HIGH` (two entries; they are OR-ed). One `Finding` per `(finding, vulnerablePackage)`.
- Mapping: `cve` = `packageVulnerabilityDetails.vulnerabilityId`; `title` = finding `title`; `is_java` = `packageManager in JAVA_MANAGERS`; name `g:a` → group/artifact; a name without `:` → `group=None`, artifact = name, or, when `filePath` ends in `<artifact>-<version>.jar`, the artifact parsed from the jar name; `fixed_versions` = `fixedInVersion` split on commas/whitespace, dropping empty and `NotAvailable`; `services=[image.service]`.
- Findings with the same `key` across images are merged, with `services` unioned and sorted.

- [ ] **Step 1: Write failing tests** (`botocore.stub.Stubber` on a real `inspector2` client)

```python
def test_scan_ready_true(): ...        # coverage fixture, ACTIVE/SUCCESSFUL → True
def test_scan_pending(): ...           # reason "PENDING_INITIAL_SCAN" → False
def test_scan_no_record(): ...         # empty page → False
def test_scan_ready_paginates(): ...   # record on second page (nextToken) → True          (Review Focus 5)
def test_maps_java_fixture():
    f = list_findings(client, [img])[0]   # from inspector_finding_java.json
    assert f.is_java and f.group and f.artifact and f.version and f.severity in ("CRITICAL", "HIGH") and f.cve.startswith("CVE-")
def test_maps_os_fixture(): assert list_findings(client, [img])[0].is_java is False
def test_filter_sent(): ...            # stub expected_params asserts the exact filterCriteria above
def test_group_missing_uses_jar_name(): # name "jackson-databind", filePath ".../jackson-databind-2.15.2.jar" → group None, artifact "jackson-databind"
def test_fixed_versions_parsing():     # "2.15.4, 2.16.1" → ["2.15.4","2.16.1"]; "NotAvailable" → []; missing → []
def test_findings_paginate(): ...      # two pages → both returned                          (Review Focus 5)
def test_merge_across_images(): ...    # same key from images of svc-b and svc-a → one Finding, services == ["svc-a", "svc-b"]
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: Inspector gateway`.

---

### Task 9: Deployment resolver

**Files:**
- Create: `src/vuln_ticketer/deployment.py`, `tests/test_deployment.py`, `tests/fixtures/events/pipeline_succeeded.json`

**Interfaces:**
- Produces: `resolve(detail: dict, codepipeline, ecs, ecr, codedeploy, allow_list: set[str]) -> Deployment | None`
  (`detail` is the EventBridge event's `detail`: keys `pipeline`, `execution-id`, `state`.)

Decisions:
- Return `None` when: `allow_list` is non-empty and the pipeline is not in it; no action with category `Source` and provider `CodeCommit`; no ECS deploy action; no ECR image found.
- Paginate `list_action_executions(pipelineName, filter={"pipelineExecutionId": id})`.
- Source: `input.configuration.RepositoryName`, `.BranchName`; commit from `output.outputVariables.CommitId`, falling back to `get_pipeline_execution(...).pipelineExecution.artifactRevisions[0].revisionId`.
- Deploy actions (category `Deploy`): provider `ECS` → `configuration.ClusterName`, `.ServiceName`. Provider `CodeDeployToECS` → `codedeploy.get_deployment_group(applicationName=configuration.ApplicationName, deploymentGroupName=configuration.DeploymentGroupName)` → each `ecsServices[]` (`clusterName`, `serviceName`).
- Per service: `ecs.describe_services` → `taskDefinition` → `ecs.describe_task_definition` → each container `image`. Keep URIs matching `<acct>.dkr.ecr.<region>.amazonaws.com/<repo>[:tag|@sha256:…]`. A URI with `@sha256:` supplies the digest; otherwise `ecr.describe_images(repositoryName, imageIds=[{"imageTag": tag or "latest"}])` → `imageDigest`. An image that ECR cannot find is skipped. Duplicate `(ecr_repo, digest)` pairs are kept once (first service wins).

- [ ] **Step 1: Write failing tests** (Stubber on real clients)

```python
def test_resolves_standard_ecs():
    d = resolve(detail, cp, ecs, ecr, cd, set())
    assert (d.repo, d.branch, d.commit, d.pipeline, d.execution_id) == ("orders-svc", "main", "abc123def", "orders-pipeline", "exec-1")
    assert d.images == [Image("orders", "orders-svc", "sha256:aaa", "111111111111.dkr.ecr.eu-west-1.amazonaws.com/orders-svc:abc123d")]
def test_allow_list_blocks(): assert resolve(detail, cp, ecs, ecr, cd, {"other"}) is None      # no AWS calls made
def test_allow_list_allows(): assert resolve(detail, cp, ecs, ecr, cd, {"orders-pipeline"}) is not None
def test_no_codecommit_source(): ...   # provider "GitHub" → None
def test_no_ecs_deploy(): ...          # only an S3 deploy → None
def test_codedeploy_blue_green(): ...  # CodeDeployToECS → get_deployment_group → service resolved
def test_digest_in_uri(): ...          # image "…/orders-svc@sha256:bbb" → digest "sha256:bbb", describe_images not called
def test_non_ecr_image_skipped(): ...  # sidecar "public.ecr.aws/datadog/agent:7" ignored; None if it was the only one
def test_two_services_same_image(): ...# one Image
def test_actions_paginate(): ...       # deploy action on page 2                              (Review Focus 5)
def test_commit_fallback(): ...        # no outputVariables → revisionId from get_pipeline_execution
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: deployment resolver`.

---

### Task 10: Ticket rendering and diff

**Files:**
- Create: `src/vuln_ticketer/ticket.py`, `tests/test_ticket.py`

**Interfaces:**
- Consumes: `Report`, `Suggestion`, `Finding`, `TicketPlan`.
- Produces:

```python
MAX_DESCRIPTION = 32767
KEYS_HEADER = "pom-vuln-bot finding keys (do not edit)"
render_description(report: Report) -> str
parse_finding_keys(description: str | None) -> set[str] | None    # None when the block is absent or unreadable
summary_for(report: Report) -> str
plan_ticket(report: Report, existing_description: str | None, has_open_ticket: bool) -> TicketPlan
```

Exact copy:
- Summary: `[{repo}] Dependency vulnerabilities: {total} findings ({critical} critical, {high} high)`.
- Description sections, in order, using wiki markup (`h2.` headings, `{code:xml}…{code}`, `||` tables):
  1. `*Repository:* {repo} | *Branch:* {branch} | *Commit:* {commit[:8]} | *Pipeline:* {pipeline}` then `*Images:* ` + comma-joined `{service}: {ecr_repo}@{digest[:19]}`.
  2. The headline in a `{panel}` when present. When `pom_missing`: `{warning}pom.xml could not be read at this commit; changes below are generic pins.{warning}`.
  3. `h2. Suggested POM changes` — per suggestion: `h3. {group}:{artifact} {current joined by ", "} → {target}`; a line `File: {pom_file} · Section: {section} · {kind label}`; ` (not verified against the Maven repository)` appended when `verified` is false; CVE list `* {cve} ({severity})`; the snippet in `{code:xml}`; `Alternative: set property {override_property} in <properties>.` when present; the `note` when present. Kind labels: direct → `Direct dependency`, property → `Version property`, managed → `Project dependencyManagement`, boot → `Managed by Spring Boot`, pin → `Transitive pin`.
  4. `h2. No fix available yet` — `* {group}:{artifact} {version} — {cve} ({severity})`. Omitted when empty.
  5. `h2. Not fixable in the POM` — one line `{critical} critical, {high} high in non-Java packages (base image or OS).` then the top five (CRITICAL first) as `* {artifact} {version} — {cve} ({severity})`. Omitted when empty.
  6. `{noformat:title=<KEYS_HEADER>}` + one key per line + `{noformat}`.
- Text taken from Inspector or the POM (titles, artifact names) has `{`, `}`, `|`, `[`, `]`, `*` backslash-escaped outside code blocks.
- Over `MAX_DESCRIPTION`: first re-render suggestions whose highest severity is HIGH as one line each (`* {group}:{artifact} {current} → {target} ({n} CVEs) — {section} in {pom_file}`); if still over, drop suggestions from the end and add `_{n} more suggestions omitted; see AWS Inspector._`. The key block is never truncated.

`plan_ticket` rules:

| `has_open_ticket` | findings (`counts().total`) | result |
|---|---|---|
| False | > 0 | `create`, with summary, description, `priority_severity` |
| False | 0 | `none` |
| True | 0 | `close`, comment `All critical and high findings resolved as of {commit[:8]} (pipeline {pipeline}).` |
| True | > 0, keys equal | `none` |
| True | > 0, keys differ | `update`, comment `Deploy {commit[:8]} via {pipeline}: {r} resolved, {n} new, {u} unchanged` followed by `New:` and `Resolved:` bullet lists of keys (each list capped at 20 with `…and {k} more`) |
| True | > 0, old keys unreadable | `update`, comment `Deploy {commit[:8]} via {pipeline}: previous ticket state could not be read; description regenerated.` |

`priority_severity` is `CRITICAL` if any finding is critical, else `HIGH`.

- [ ] **Step 1: Write failing tests**

```python
def test_summary(): assert summary_for(report) == "[orders-svc] Dependency vulnerabilities: 4 findings (2 critical, 2 high)"
def test_description_sections_in_order(): ...     # index of each h2 heading ascending; headline panel before first h2
def test_snippet_in_code_block(): assert "{code:xml}\n<commons-text.version>1.10.0</commons-text.version>\n{code}" in d
def test_unverified_marker(): assert "(not verified against the Maven repository)" in d
def test_override_line(): assert "Alternative: set property jackson-bom.version=2.15.4 in <properties>." in d
def test_empty_sections_omitted(): assert "No fix available yet" not in d and "Not fixable in the POM" not in d
def test_non_pom_top_five(): ...                  # 7 non-POM findings → count line + exactly 5 bullets, CRITICAL first
def test_pom_missing_warning(): assert "pom.xml could not be read" in d
def test_escapes_markup(): ...                    # artifact "we|ird{x}" → "we\\|ird\\{x\\}" in heading
def test_keys_round_trip(): assert parse_finding_keys(render_description(report)) == set(report.finding_keys)
def test_parse_keys_absent(): assert parse_finding_keys("someone rewrote this") is None and parse_finding_keys(None) is None
def test_truncation():                            # 400 HIGH suggestions + 1 CRITICAL
    assert len(d) <= MAX_DESCRIPTION and "more suggestions omitted" in d and "{code:xml}" in d   # critical keeps its snippet
    assert parse_finding_keys(d) == set(report.finding_keys)
def test_plan_create(): p = plan_ticket(report, None, False); assert p.action == "create" and p.priority_severity == "CRITICAL"
def test_plan_none_when_clean_and_no_ticket(): assert plan_ticket(empty, None, False).action == "none"
def test_plan_close(): p = plan_ticket(empty, old_desc, True); assert p.action == "close" and "resolved as of abc123de" in p.comment
def test_plan_unchanged(): assert plan_ticket(report, render_description(report), True).action == "none"
def test_plan_update_diff(): assert p.action == "update" and "2 resolved, 1 new, 6 unchanged" in p.comment
def test_plan_update_human_edited():              # Review Focus 4
    p = plan_ticket(report, "someone rewrote this", True); assert p.action == "update" and "could not be read" in p.comment
def test_priority_high_only(): assert plan_ticket(high_only, None, False).priority_severity == "HIGH"
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: ticket rendering and change detection`.

---

### Task 11: JIRA client

**Files:**
- Create: `src/vuln_ticketer/jira.py`, `tests/test_jira.py`

**Interfaces — Produces:**

```python
class JiraError(Exception): status: int          # 4xx — do not retry
class JiraUnavailable(Exception)                 # 5xx, timeouts, connection errors — retryable
class JiraClient:
    def __init__(self, base_url: str, token: str, session: requests.Session | None = None, timeout: float = 15)
    def find_open_issue(self, project: str, repo: str) -> dict | None      # {"key": str, "description": str} of the newest match
    def create_issue(self, project: str, issue_type: str, summary: str, description: str, priority: str | None, repo: str) -> str
    def update_issue(self, key: str, summary: str, description: str, priority: str | None) -> None
    def add_comment(self, key: str, body: str) -> None
    def transition(self, key: str, name: str) -> bool                      # False when no transition has that name (case-insensitive)
```

Decisions: endpoints `POST /rest/api/2/search` (body `{"jql", "fields": ["description"], "maxResults": 5}`), `POST /rest/api/2/issue`, `PUT /rest/api/2/issue/{key}`, `POST /rest/api/2/issue/{key}/comment`, `GET` and `POST /rest/api/2/issue/{key}/transitions`. JQL exactly: `project = "{project}" AND labels = "pom-vuln-bot" AND labels = "repo-{repo}" AND statusCategory != Done ORDER BY created DESC`. Created issues carry labels `["pom-vuln-bot", "repo-{repo}"]`. `priority=None` omits the field. More than one search hit → use the first and log a warning listing the other keys. A trailing slash on `base_url` is tolerated.

- [ ] **Step 1: Write failing tests** (`responses`)

```python
def test_bearer_header(): assert responses.calls[0].request.headers["Authorization"] == "Bearer tok"
def test_find_jql(): assert json.loads(responses.calls[0].request.body)["jql"] == 'project = "ORD" AND labels = "pom-vuln-bot" AND labels = "repo-orders-svc" AND statusCategory != Done ORDER BY created DESC'
def test_find_none(): assert client.find_open_issue("ORD", "orders-svc") is None
def test_find_newest_of_two(): assert client.find_open_issue("ORD", "orders-svc") == {"key": "ORD-9", "description": "d"}
def test_create(): ...        # returns "ORD-10"; body fields: project.key, issuetype.name, summary, description, priority.name, labels
def test_create_without_priority(): assert "priority" not in body["fields"]
def test_update(): ...        # PUT body fields summary/description/priority
def test_comment(): ...       # POST body {"body": "..."}
def test_transition_found(): assert client.transition("ORD-9", "done") is True and posted["transition"]["id"] == "31"
def test_transition_missing(): assert client.transition("ORD-9", "Done") is False      # no POST made
def test_4xx_raises_jira_error(): ...    # 401 → JiraError with status 401
def test_5xx_and_timeout_raise_unavailable(): ...
def test_trailing_slash(): JiraClient("https://jira.corp/", "t")...; assert url == "https://jira.corp/rest/api/2/search"
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS. **Step 5:** Commit `feat: JIRA Data Center client`.

---

### Task 12: Config and Lambda handlers

**Files:**
- Create: `src/vuln_ticketer/config.py`, `src/vuln_ticketer/handlers.py`, `tests/test_config.py`, `tests/test_handlers.py`

**Interfaces:**
- Consumes: everything above.
- Produces:

```python
# config.py
Settings.from_env() -> Settings   # fields: config_parameter (CONFIG_PARAMETER), jira_base_url (JIRA_BASE_URL),
                                  # jira_token_secret_arn (JIRA_TOKEN_SECRET_ARN), maven_repo_url (MAVEN_REPO_URL),
                                  # pipeline_allow_list: set[str] (PIPELINE_ALLOW_LIST, comma-separated), report_bucket (REPORT_BUCKET)
Config(default_project: str | None, issue_type: str = "Task", done_transition: str = "Done",
       priority_map: dict[str, str] = {"CRITICAL": "Highest", "HIGH": "High"}, repos: dict[str, dict] = {})
    .project_for(repo: str) -> str | None ; .pom_path_for(repo: str) -> str      # default "pom.xml"
load_config(ssm, name: str) -> Config        # JSON document, shape as in the spec's Configuration section

# handlers.py — Step Functions task inputs/outputs
resolve_handler(event, ctx)  # in: EventBridge event → {"status": "SKIPPED", "reason": str} | {"status": "RESOLVED", "deployment": {...}}
wait_handler(event, ctx)     # in: {"deployment": {...}}  → {"ready": bool}
analyze_handler(event, ctx)  # in: {"deployment": {...}}  → {"reportRef": {"bucket": str, "key": str}, "findings": int}
publish_handler(event, ctx)  # in: {"reportRef": {...}}   → {"action": "create"|"update"|"close"|"none", "issueKey": str | None}
publish(plan: TicketPlan, existing: dict | None, client: JiraClient, cfg: Config, project: str, repo: str) -> str | None
```

Decisions:
- `resolve_handler` skip reasons, exactly: `"pipeline not handled"` (resolver returned `None`), `"no JIRA project for repo"` (no mapping and no default). It loads the SSM config to check the latter.
- `analyze_handler`: `inspector.list_findings` → `load_project` with a fetch function over `codecommit.get_file(repositoryName, commitSpecifier=commit, filePath=path)` (`FileDoesNotExistException` → `None`) → `analyze` → writes `Report.to_dict()` as JSON to `s3://{REPORT_BUCKET}/reports/{execution_id}.json`.
- `publish_handler`: reads the report, resolves project, fetches the PAT from Secrets Manager (plain string secret), `find_open_issue`, `plan_ticket`, `publish`.
- `publish`: `create` → `create_issue`, return key. `update` → `update_issue` then `add_comment`. `close` → `add_comment`, then `transition(cfg.done_transition)`; a `False` result is logged, not an error. `none` → nothing. Priority = `cfg.priority_map.get(plan.priority_severity)`.
- AWS clients are created at module import (reused across invocations) and are patchable in tests. Every log line carries `executionId`.
- `JiraUnavailable` propagates under that class name (Step Functions retries it); `JiraError` propagates and is not retried.

- [ ] **Step 1: Write failing tests**

```python
def test_settings_from_env(monkeypatch): ...   # PIPELINE_ALLOW_LIST="a, b" → {"a","b"}; "" → set()
def test_config_defaults(): c = load_config(ssm_stub('{"defaultProject":"PLAT"}'), "n"); assert (c.issue_type, c.done_transition, c.priority_map) == ("Task", "Done", {"CRITICAL": "Highest", "HIGH": "High"})
def test_project_and_pom_path():
    c = load_config(ssm_stub('{"defaultProject":"PLAT","repos":{"orders-svc":{"jiraProject":"ORD","pomPath":"service/pom.xml"}}}'), "n")
    assert c.project_for("orders-svc") == "ORD" and c.project_for("other") == "PLAT"
    assert c.pom_path_for("orders-svc") == "service/pom.xml" and c.pom_path_for("other") == "pom.xml"
def test_no_default_project(): assert load_config(ssm_stub('{"repos":{}}'), "n").project_for("x") is None

def test_resolve_skipped_pipeline(): assert resolve_handler(evt, None) == {"status": "SKIPPED", "reason": "pipeline not handled"}
def test_resolve_skipped_no_project(): assert out == {"status": "SKIPPED", "reason": "no JIRA project for repo"}
def test_resolve_ok(): assert out["status"] == "RESOLVED" and Deployment.from_dict(out["deployment"]).repo == "orders-svc"
def test_wait_ready_and_not_ready(): ...       # {"ready": True} / {"ready": False}
def test_analyze_writes_report(): ...          # S3 put_object Key "reports/exec-1.json"; body round-trips via Report.from_dict; "findings" == 2
def test_analyze_missing_pom(): ...            # get_file raises FileDoesNotExistException → report.pom_missing is True
def test_publish_create(): assert publish(create_plan, None, fake_jira, cfg, "ORD", "orders-svc") == "ORD-10"   # priority "Highest"
def test_publish_update_calls_update_then_comment(): assert fake_jira.calls == ["update_issue", "add_comment"]
def test_publish_close_without_transition(): ...   # transition returns False → no exception, calls == ["add_comment", "transition"]
def test_publish_none(): assert fake_jira.calls == []
def test_publish_handler_end_to_end(): ...     # stubs S3/Secrets/SSM + fake JIRA → {"action": "create", "issueKey": "ORD-10"}
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run the whole suite `.venv/bin/pytest -q` → PASS. **Step 5:** Commit `feat: config and Lambda handlers`.

---

### Task 13: SAM template, state machine, README

**Files:**
- Create: `template.yaml`, `statemachine/workflow.asl.json`, `README.md`, `tests/test_workflow.py`

**Interfaces:**
- Consumes: handler names and their input/output shapes from Task 12.

Decisions — `template.yaml`:
- Parameters: `JiraBaseUrl` (pattern `https?://.+`), `JiraTokenSecretArn`, `ConfigParameterName` (default `/pom-vuln-ticketer/config`), `VpcSubnetIds` (`List<AWS::EC2::Subnet::Id>`), `VpcSecurityGroupIds` (`List<AWS::EC2::SecurityGroup::Id>`), `MavenRepoUrl` (default `https://repo1.maven.org/maven2`), `PipelineAllowList` (default `""`), `AlarmTopicArn` (default `""`), `ScanWaitSeconds` (default 120), `ScanMaxAttempts` (default 15).
- Globals: `python3.12`, `arm64`, `CodeUri: src/`, memory 512.
- Functions: `ResolveFunction` (timeout 60), `WaitFunction` (30), `AnalyzeFunction` (300), `PublishFunction` (60, `VpcConfig` from the parameters, `ReservedConcurrentExecutions: 1`). IAM per function exactly as in the spec's IAM section, plus `codedeploy:GetDeploymentGroup` and `ssm:GetParameter` for Resolve.
- `ReportBucket`: private, SSE-S3, lifecycle expiry 30 days, public access blocked.
- `Workflow` (`AWS::Serverless::StateMachine`, STANDARD, `DefinitionUri: statemachine/workflow.asl.json`, `DefinitionSubstitutions` for the four ARNs and the two scan parameters) with an `EventBridgeRule` event: `source: [aws.codepipeline]`, `detail-type: [CodePipeline Pipeline Execution State Change]`, `detail.state: [SUCCEEDED]`.
- `WorkflowFailedAlarm` on `AWS/States` `ExecutionsFailed` ≥ 1 in 5 minutes; `AlarmActions` only when `AlarmTopicArn` is set (condition).

Decisions — `workflow.asl.json` states: `Resolve` (Task) → `Resolved?` (Choice on `$.resolve.status`; `SKIPPED` → `Skipped` Succeed) → `InitAttempts` (Pass, `attempt = 0`) → `CheckScan` (Task) → `ScanReady?` (Choice: `ready` → `Analyze`; `attempt >= ${ScanMaxAttempts}` → `ScanTimeout` Succeed with comment `SKIPPED_SCAN_TIMEOUT`; else `WaitForScan`) → `WaitForScan` (Wait `${ScanWaitSeconds}`) → `Increment` (Pass, `States.MathAdd`) → `CheckScan`. `Analyze` → `Publish` → `Done` Succeed. Every Task has `Retry` on `States.TaskFailed` with `MaxAttempts: 3`, `IntervalSeconds: 5`, `BackoffRate: 2`; `Publish` additionally lists `JiraError` first with `MaxAttempts: 0`.

README sections: what it does (three sentences), prerequisites (Inspector ECR enhanced scanning on; the Lambda subnets need NAT or VPC endpoints for Secrets Manager, SSM and S3; a JIRA PAT whose user can create, edit, comment and transition issues in the mapped projects), the SSM config document with the spec's example, deploy commands (`sam build && sam deploy --guided`), the dry-run command from Task 14, and how tickets behave (the spec's behaviour table).

- [ ] **Step 1: Write failing test `tests/test_workflow.py`**

```python
def test_workflow_shape():
    wf = json.load(open("statemachine/workflow.asl.json"))
    assert wf["StartAt"] == "Resolve"
    assert set(wf["States"]) == {"Resolve", "Resolved?", "Skipped", "InitAttempts", "CheckScan", "ScanReady?", "WaitForScan", "Increment", "ScanTimeout", "Analyze", "Publish", "Done"}
    for name, s in wf["States"].items():            # every Next/Default/Choices target exists
        for target in next_targets(s): assert target in wf["States"], (name, target)
    assert wf["States"]["Publish"]["Retry"][0] == {"ErrorEquals": ["JiraError"], "MaxAttempts": 0}
def test_template_publish_function_is_in_vpc_with_concurrency_one(): ...   # parse template.yaml with a loader that ignores !Ref/!Sub tags
def test_template_rule_pattern(): ...               # detail.state == ["SUCCEEDED"]
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Write the three files. **Step 4:** Run → PASS, then `sam validate --lint` → `is a valid SAM Template` (if the SAM CLI is not installed, use `../codecommit-pr/.venv-sam/bin/sam`). **Step 5:** Commit `feat: SAM template, workflow and README`.

---

### Task 14: Replay script and live dry run

**Files:**
- Create: `scripts/replay.py`, `tests/test_replay.py`

**Interfaces:**
- Consumes: `deployment.resolve`, `inspector.scan_ready`, `inspector.list_findings`, `pom.load_project`, `analyzer.analyze`, `ticket.plan_ticket`, `ticket.render_description`, `config.load_config`, `handlers.publish`.
- Produces: `main(argv: list[str]) -> int`; CLI `scripts/replay.py <pipeline> <execution-id> [--dry-run] [--config-parameter NAME] [--maven-repo-url URL] [--jira-base-url URL] [--jira-token-env VAR]`.

Decisions: `--dry-run` never contacts JIRA: it plans as if no ticket exists and prints the summary, then the description, to stdout. Without `--dry-run` it requires `--jira-base-url` and a token in the named environment variable (default `JIRA_TOKEN`), and publishes. Exit codes: `0` done, `2` pipeline not handled or no JIRA project, `3` scan not ready (it does not wait).

- [ ] **Step 1: Write failing tests** (module functions patched)

```python
def test_dry_run_prints_ticket(capsys): assert main(["orders-pipeline", "exec-1", "--dry-run"]) == 0; out = capsys.readouterr().out; assert "[orders-svc] Dependency vulnerabilities" in out and "h2. Suggested POM changes" in out
def test_dry_run_does_not_touch_jira(): ...     # JiraClient constructor not called
def test_not_handled_exit_2(): ...
def test_scan_not_ready_exit_3(): ...
def test_live_requires_jira_url(): ...          # no --dry-run and no --jira-base-url → SystemExit
```

- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run the whole suite → PASS.

- [ ] **Step 5: Live dry run.** With your human partner's AWS credentials, pick a recent successful execution (`aws codepipeline list-pipeline-executions --pipeline-name <p> --max-items 3`) and run `.venv/bin/python scripts/replay.py <pipeline> <execution-id> --dry-run`. Show them the printed ticket. Check three suggestions by hand against the repo's `pom.xml` and Maven Central. If credentials are not available, **stop and ask**; do not mark this step done without the run.

- [ ] **Step 6:** Commit `feat: replay script`.
