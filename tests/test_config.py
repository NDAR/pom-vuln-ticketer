import json

import pytest

from vuln_ticketer.config import Settings, load_config


class FakeSsm:
    def __init__(self, value):
        self.value, self.names = value, []

    def get_parameter(self, Name):
        self.names.append(Name)
        return {"Parameter": {"Value": self.value}}


def test_settings_from_env(monkeypatch):
    for k, v in {"CONFIG_PARAMETER": "/p", "JIRA_BASE_URL": "https://jira.corp", "JIRA_TOKEN_SECRET_ARN": "arn:s",
                 "MAVEN_REPO_URL": "https://nexus/repo", "PIPELINE_ALLOW_LIST": "a, b", "REPORT_BUCKET": "bkt"}.items():
        monkeypatch.setenv(k, v)
    s = Settings.from_env()
    assert (s.config_parameter, s.jira_base_url, s.jira_token_secret_arn, s.maven_repo_url, s.report_bucket) == (
        "/p", "https://jira.corp", "arn:s", "https://nexus/repo", "bkt")
    assert s.pipeline_allow_list == {"a", "b"}


def test_settings_defaults(monkeypatch):
    for k in ("CONFIG_PARAMETER", "JIRA_BASE_URL", "JIRA_TOKEN_SECRET_ARN", "MAVEN_REPO_URL", "REPORT_BUCKET"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PIPELINE_ALLOW_LIST", "")
    s = Settings.from_env()
    assert s.pipeline_allow_list == set() and s.maven_repo_url == "https://repo1.maven.org/maven2"


def test_config_defaults():
    ssm = FakeSsm('{"defaultProject":"PLAT"}')
    c = load_config(ssm, "n")
    assert (c.issue_type, c.done_transition, c.priority_map) == ("Task", "Done", {"CRITICAL": "Highest", "HIGH": "High"})
    assert ssm.names == ["n"]


def test_config_overrides():
    c = load_config(FakeSsm(json.dumps({"issueType": "Bug", "doneTransition": "Close Issue",
                                        "priorityMap": {"CRITICAL": "Blocker", "HIGH": "Major"}})), "n")
    assert (c.issue_type, c.done_transition, c.priority_map) == ("Bug", "Close Issue", {"CRITICAL": "Blocker", "HIGH": "Major"})


def test_project_and_pom_path():
    c = load_config(FakeSsm('{"defaultProject":"PLAT","repos":{"orders-svc":{"jiraProject":"ORD","pomPath":"service/pom.xml"}}}'), "n")
    assert c.project_for("orders-svc") == "ORD" and c.project_for("other") == "PLAT"
    assert c.pom_path_for("orders-svc") == "service/pom.xml" and c.pom_path_for("other") == "pom.xml"


def test_repo_without_project_uses_default():
    c = load_config(FakeSsm('{"defaultProject":"PLAT","repos":{"x":{"pomPath":"a/pom.xml"}}}'), "n")
    assert c.project_for("x") == "PLAT" and c.pom_path_for("x") == "a/pom.xml"


def test_no_default_project():
    assert load_config(FakeSsm('{"repos":{}}'), "n").project_for("x") is None


def test_invalid_json_is_an_error():
    with pytest.raises(ValueError):
        load_config(FakeSsm("not json"), "n")
