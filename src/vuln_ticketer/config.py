"""Environment settings and the per-repo configuration document in SSM Parameter Store."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .maven_repo import DEFAULT_BASE_URL

DEFAULT_PRIORITY_MAP = {"CRITICAL": "Highest", "HIGH": "High"}


@dataclass
class Settings:
    config_parameter: str
    jira_base_url: str
    jira_token_secret_arn: str
    maven_repo_url: str
    pipeline_allow_list: set[str]
    report_bucket: str

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ
        return cls(
            config_parameter=env.get("CONFIG_PARAMETER", "/pom-vuln-ticketer/config"),
            jira_base_url=env.get("JIRA_BASE_URL", ""),
            jira_token_secret_arn=env.get("JIRA_TOKEN_SECRET_ARN", ""),
            maven_repo_url=env.get("MAVEN_REPO_URL") or DEFAULT_BASE_URL,
            pipeline_allow_list={p.strip() for p in env.get("PIPELINE_ALLOW_LIST", "").split(",") if p.strip()},
            report_bucket=env.get("REPORT_BUCKET", ""),
        )


@dataclass
class Config:
    default_project: str | None = None
    issue_type: str = "Task"
    done_transition: str = "Done"
    priority_map: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_PRIORITY_MAP))
    repos: dict[str, dict] = field(default_factory=dict)

    def project_for(self, repo: str) -> str | None:
        return self.repos.get(repo, {}).get("jiraProject") or self.default_project

    def pom_path_for(self, repo: str) -> str:
        return self.repos.get(repo, {}).get("pomPath") or "pom.xml"


def load_config(ssm, name: str) -> Config:
    raw = ssm.get_parameter(Name=name)["Parameter"]["Value"]
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"SSM parameter {name} is not valid JSON: {e}") from e
    return Config(
        default_project=doc.get("defaultProject"),
        issue_type=doc.get("issueType", "Task"),
        done_transition=doc.get("doneTransition", "Done"),
        priority_map=doc.get("priorityMap") or dict(DEFAULT_PRIORITY_MAP),
        repos=doc.get("repos") or {},
    )
