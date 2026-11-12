import importlib.util
from pathlib import Path

import pytest
from fakes import GUAVA, FakeRepo, java_finding, make_deployment, read
from test_handlers import CONFIG, FakeCodeCommit, FakeJira, FakeSsm

from vuln_ticketer import handlers

_spec = importlib.util.spec_from_file_location("replay", Path(__file__).parent.parent / "scripts" / "replay.py")
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


@pytest.fixture
def world(monkeypatch):
    clients = {"ssm": FakeSsm(CONFIG), "codecommit": FakeCodeCommit({"pom.xml": read("simple.xml")})}
    for name in ("codepipeline", "ecs", "ecr", "codedeploy", "inspector2"):
        clients[name] = object()
    monkeypatch.setattr(handlers, "_CLIENTS", clients)
    monkeypatch.setattr(handlers, "MavenRepo", lambda url: FakeRepo())
    monkeypatch.setattr(handlers.deployment, "resolve", lambda *a: make_deployment())
    monkeypatch.setattr(handlers.inspector, "scan_ready", lambda client, images: True)
    monkeypatch.setattr(handlers.inspector, "list_findings",
                        lambda client, images: [java_finding(GUAVA, "32.0.0-jre", ["32.0.1"], "CVE-2", "CRITICAL")])
    monkeypatch.delenv("JIRA_TOKEN", raising=False)

    def no_jira(*a, **k):
        raise AssertionError("JIRA must not be contacted")

    monkeypatch.setattr(handlers, "JiraClient", no_jira)
    return clients


def test_dry_run_prints_ticket(world, capsys):
    assert replay.main(["orders-pipeline", "exec-1", "--dry-run"]) == 0  # JiraClient would raise if constructed
    out = capsys.readouterr().out
    assert "[orders-svc] Dependency vulnerabilities: 1 findings (1 critical, 0 high)" in out
    assert "h2. Suggested POM changes" in out and "<version>32.0.1-jre</version>" in out


def test_dry_run_passes_pipeline_and_execution(world, monkeypatch):
    seen = {}
    monkeypatch.setattr(handlers.deployment, "resolve", lambda detail, *a: seen.update(detail) or make_deployment())
    replay.main(["orders-pipeline", "exec-1", "--dry-run"])
    assert seen == {"pipeline": "orders-pipeline", "execution-id": "exec-1"}


def test_dry_run_with_no_findings(world, monkeypatch, capsys):
    monkeypatch.setattr(handlers.inspector, "list_findings", lambda client, images: [])
    assert replay.main(["orders-pipeline", "exec-1", "--dry-run"]) == 0
    assert "No critical or high findings" in capsys.readouterr().out


def test_dry_run_works_without_ssm_config(world, monkeypatch, capsys):
    from botocore.exceptions import ClientError

    def missing(Name):
        raise ClientError({"Error": {"Code": "ParameterNotFound", "Message": "nope"}}, "GetParameter")

    monkeypatch.setattr(world["ssm"], "get_parameter", missing)
    assert replay.main(["orders-pipeline", "exec-1", "--dry-run"]) == 0
    assert "h2. Suggested POM changes" in capsys.readouterr().out


def test_not_handled_exit_2(world, monkeypatch):
    monkeypatch.setattr(handlers.deployment, "resolve", lambda *a: None)
    assert replay.main(["orders-pipeline", "exec-1", "--dry-run"]) == 2


def test_no_project_exit_2_when_publishing(world, monkeypatch):
    world["ssm"].config = {"repos": {}}
    monkeypatch.setenv("JIRA_TOKEN", "tok")
    assert replay.main(["orders-pipeline", "exec-1", "--jira-base-url", "https://jira.corp"]) == 2


def test_scan_not_ready_exit_3(world, monkeypatch):
    monkeypatch.setattr(handlers.inspector, "scan_ready", lambda client, images: False)
    assert replay.main(["orders-pipeline", "exec-1", "--dry-run"]) == 3


def test_live_requires_jira_url(world):
    with pytest.raises(SystemExit):
        replay.main(["orders-pipeline", "exec-1"])


def test_live_requires_token(world):
    with pytest.raises(SystemExit):
        replay.main(["orders-pipeline", "exec-1", "--jira-base-url", "https://jira.corp"])


def test_live_publishes(world, monkeypatch, capsys):
    jira, made = FakeJira(), {}
    monkeypatch.setattr(handlers, "JiraClient", lambda base_url, token: made.update(url=base_url, token=token) or jira)
    monkeypatch.setenv("MY_TOKEN", "tok")
    assert replay.main(["orders-pipeline", "exec-1", "--jira-base-url", "https://jira.corp", "--jira-token-env", "MY_TOKEN"]) == 0
    assert jira.calls == ["create_issue"] and made == {"url": "https://jira.corp", "token": "tok"}
    assert "create ORD-10" in capsys.readouterr().out
