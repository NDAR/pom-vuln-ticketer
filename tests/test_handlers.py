import io
import json

import pytest
from botocore.exceptions import ClientError
from fakes import DATABIND, FIXTURES, GUAVA, FakeRepo, java_finding, make_deployment, read

from vuln_ticketer import handlers
from vuln_ticketer.config import Config
from vuln_ticketer.jira import JiraUnavailable
from vuln_ticketer.models import Deployment, Report, TicketPlan

EVENT = json.loads((FIXTURES / "events" / "pipeline_succeeded.json").read_text())
CONFIG = {"defaultProject": "PLAT", "repos": {"orders-svc": {"jiraProject": "ORD"}}}


class FakeSsm:
    def __init__(self, config):
        self.config = config

    def get_parameter(self, Name):
        return {"Parameter": {"Value": json.dumps(self.config)}}


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode()

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}


class FakeSecrets:
    def get_secret_value(self, SecretId):
        return {"SecretString": "tok"}


class FakeCodeCommit:
    def __init__(self, files):
        self.files, self.calls = files, []

    def get_file(self, repositoryName, commitSpecifier, filePath):
        self.calls.append((repositoryName, commitSpecifier, filePath))
        if filePath not in self.files:
            raise ClientError({"Error": {"Code": "FileDoesNotExistException", "Message": "nope"}}, "GetFile")
        return {"fileContent": self.files[filePath].encode()}


class FakeJira:
    def __init__(self, existing=None, transition_ok=True):
        self.existing, self.transition_ok, self.calls, self.args = existing, transition_ok, [], {}

    def find_open_issue(self, project, repo):
        return self.existing

    def create_issue(self, project, issue_type, summary, description, priority, repo):
        self.calls.append("create_issue")
        self.args = dict(project=project, issue_type=issue_type, priority=priority, repo=repo)
        return "ORD-10"

    def update_issue(self, key, summary, description, priority):
        self.calls.append("update_issue")
        self.args = dict(key=key, priority=priority)

    def add_comment(self, key, body):
        self.calls.append("add_comment")

    def transition(self, key, name):
        self.calls.append("transition")
        self.args["transition"] = name
        return self.transition_ok


@pytest.fixture
def env(monkeypatch):
    for k, v in {"CONFIG_PARAMETER": "/cfg", "JIRA_BASE_URL": "https://jira.corp", "JIRA_TOKEN_SECRET_ARN": "arn:s",
                 "MAVEN_REPO_URL": "https://repo1.maven.org/maven2", "PIPELINE_ALLOW_LIST": "", "REPORT_BUCKET": "bkt"}.items():
        monkeypatch.setenv(k, v)
    clients = {"ssm": FakeSsm(CONFIG), "s3": FakeS3(), "secretsmanager": FakeSecrets(),
               "codecommit": FakeCodeCommit({"pom.xml": read("simple.xml")})}
    for name in ("codepipeline", "ecs", "ecr", "codedeploy", "inspector2"):
        clients[name] = object()
    monkeypatch.setattr(handlers, "_CLIENTS", clients)
    monkeypatch.setattr(handlers, "MavenRepo", lambda url: FakeRepo())
    return clients


def test_resolve_skipped_pipeline(env, monkeypatch):
    monkeypatch.setattr(handlers.deployment, "resolve", lambda *a: None)
    assert handlers.resolve_handler(EVENT, None) == {"status": "SKIPPED", "reason": "pipeline not handled"}


def test_resolve_skipped_no_project(env, monkeypatch):
    env["ssm"].config = {"repos": {}}
    monkeypatch.setattr(handlers.deployment, "resolve", lambda *a: make_deployment())
    assert handlers.resolve_handler(EVENT, None) == {"status": "SKIPPED", "reason": "no JIRA project for repo"}


def test_resolve_ok(env, monkeypatch):
    seen = {}

    def fake_resolve(detail, cp, ecs, ecr, cd, allow):
        seen.update(detail=detail, allow=allow)
        return make_deployment()

    monkeypatch.setattr(handlers.deployment, "resolve", fake_resolve)
    out = handlers.resolve_handler(EVENT, None)
    assert out["status"] == "RESOLVED" and Deployment.from_dict(out["deployment"]).repo == "orders-svc"
    assert seen == {"detail": EVENT["detail"], "allow": set()}
    json.dumps(out)  # must be JSON-serialisable for Step Functions


@pytest.mark.parametrize("ready", [True, False])
def test_wait(env, monkeypatch, ready):
    monkeypatch.setattr(handlers.inspector, "scan_ready", lambda client, images: ready)
    assert handlers.wait_handler({"deployment": make_deployment().to_dict()}, None) == {"ready": ready}


def test_analyze_writes_report(env, monkeypatch):
    findings = [java_finding(DATABIND, "2.15.3", ["2.15.4"], "CVE-1"), java_finding(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-2")]
    monkeypatch.setattr(handlers.inspector, "list_findings", lambda client, images: findings)
    out = handlers.analyze_handler({"deployment": make_deployment().to_dict()}, None)
    assert out == {"reportRef": {"bucket": "bkt", "key": "reports/exec-1.json"}, "findings": 2}
    report = Report.from_dict(json.loads(env["s3"].objects[("bkt", "reports/exec-1.json")]))
    assert {s.kind for s in report.suggestions} == {"boot", "direct"} and report.pom_missing is False
    assert env["codecommit"].calls == [("orders-svc", "abc123def4567890", "pom.xml")]


def test_analyze_uses_configured_pom_path(env, monkeypatch):
    env["ssm"].config = {"repos": {"orders-svc": {"jiraProject": "ORD", "pomPath": "service/pom.xml"}}}
    monkeypatch.setattr(handlers.inspector, "list_findings", lambda client, images: [])
    handlers.analyze_handler({"deployment": make_deployment().to_dict()}, None)
    assert env["codecommit"].calls[0][2] == "service/pom.xml"


def test_analyze_missing_pom(env, monkeypatch):
    env["codecommit"].files = {}
    monkeypatch.setattr(handlers.inspector, "list_findings",
                        lambda client, images: [java_finding(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-2")])
    handlers.analyze_handler({"deployment": make_deployment().to_dict()}, None)
    report = Report.from_dict(json.loads(env["s3"].objects[("bkt", "reports/exec-1.json")]))
    assert report.pom_missing is True and report.suggestions[0].kind == "pin"


CFG = Config(default_project="PLAT")
CREATE = TicketPlan("create", summary="s", description="d", priority_severity="CRITICAL")


def test_publish_create():
    jira = FakeJira()
    assert handlers.publish(CREATE, None, jira, CFG, "ORD", "orders-svc") == "ORD-10"
    assert jira.args == {"project": "ORD", "issue_type": "Task", "priority": "Highest", "repo": "orders-svc"}


def test_publish_update_calls_update_then_comment():
    jira = FakeJira()
    plan = TicketPlan("update", summary="s", description="d", comment="c", priority_severity="HIGH")
    assert handlers.publish(plan, {"key": "ORD-9", "description": "old"}, jira, CFG, "ORD", "orders-svc") == "ORD-9"
    assert jira.calls == ["update_issue", "add_comment"] and jira.args == {"key": "ORD-9", "priority": "High"}


def test_publish_close():
    jira = FakeJira()
    handlers.publish(TicketPlan("close", comment="c"), {"key": "ORD-9", "description": ""}, jira, CFG, "ORD", "orders-svc")
    assert jira.calls == ["add_comment", "transition"] and jira.args["transition"] == "Done"


def test_publish_close_without_transition():
    jira = FakeJira(transition_ok=False)
    assert handlers.publish(TicketPlan("close", comment="c"), {"key": "ORD-9", "description": ""}, jira, CFG,
                            "ORD", "orders-svc") == "ORD-9"
    assert jira.calls == ["add_comment", "transition"]


def test_publish_none():
    jira = FakeJira()
    assert handlers.publish(TicketPlan("none"), {"key": "ORD-9", "description": ""}, jira, CFG, "ORD", "orders-svc") == "ORD-9"
    assert handlers.publish(TicketPlan("none"), None, jira, CFG, "ORD", "orders-svc") is None
    assert jira.calls == []


def _store_report(env, monkeypatch, findings):
    monkeypatch.setattr(handlers.inspector, "list_findings", lambda client, images: findings)
    return handlers.analyze_handler({"deployment": make_deployment().to_dict()}, None)


def test_publish_handler_end_to_end(env, monkeypatch):
    ref = _store_report(env, monkeypatch, [java_finding(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-2", "CRITICAL")])
    jira, made = FakeJira(), {}

    def factory(base_url, token):
        made.update(base_url=base_url, token=token)
        return jira

    monkeypatch.setattr(handlers, "JiraClient", factory)
    assert handlers.publish_handler({"reportRef": ref["reportRef"]}, None) == {"action": "create", "issueKey": "ORD-10"}
    assert made == {"base_url": "https://jira.corp", "token": "tok"} and jira.args["project"] == "ORD"


def test_publish_handler_clean_and_no_ticket(env, monkeypatch):
    ref = _store_report(env, monkeypatch, [])
    monkeypatch.setattr(handlers, "JiraClient", lambda base_url, token: FakeJira())
    assert handlers.publish_handler({"reportRef": ref["reportRef"]}, None) == {"action": "none", "issueKey": None}


def test_publish_handler_propagates_jira_unavailable(env, monkeypatch):
    ref = _store_report(env, monkeypatch, [])

    class Down(FakeJira):
        def find_open_issue(self, project, repo):
            raise JiraUnavailable("down")

    monkeypatch.setattr(handlers, "JiraClient", lambda base_url, token: Down())
    with pytest.raises(JiraUnavailable):
        handlers.publish_handler({"reportRef": ref["reportRef"]}, None)
