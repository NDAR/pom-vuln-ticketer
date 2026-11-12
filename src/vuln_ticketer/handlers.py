"""Lambda entry points, one per Step Functions task."""
from __future__ import annotations

import json

import boto3
from botocore.exceptions import ClientError

from . import deployment, inspector
from .analyzer import analyze
from .config import Config, Settings, load_config
from .jira import JiraClient
from .log import get_logger
from .maven_repo import MavenRepo
from .models import Deployment, Report, TicketPlan
from .pom import load_project
from .ticket import plan_ticket

log = get_logger("handlers")
_CLIENTS: dict = {}  # boto3 clients, created once per Lambda container
_MISSING_FILE_ERRORS = {"FileDoesNotExistException", "FileTooLargeException", "PathDoesNotExistException"}


def _client(name: str):
    if name not in _CLIENTS:
        _CLIENTS[name] = boto3.client(name)
    return _CLIENTS[name]


def resolve_handler(event, ctx):
    settings = Settings.from_env()
    detail = event["detail"]
    extra = {"executionId": detail.get("execution-id"), "pipeline": detail.get("pipeline")}
    arn = getattr(ctx, "invoked_function_arn", None)
    dep = deployment.resolve(detail, _client("codepipeline"), _client("ecs"), _client("ecr"), _client("codedeploy"),
                             settings.pipeline_allow_list, account_id=arn.split(":")[4] if arn else None)
    if dep is None:
        log.info("skipped: pipeline not handled", extra=extra)
        return {"status": "SKIPPED", "reason": "pipeline not handled"}
    if load_config(_client("ssm"), settings.config_parameter).project_for(dep.repo) is None:
        log.info("skipped: no JIRA project for repo", extra={**extra, "repo": dep.repo})
        return {"status": "SKIPPED", "reason": "no JIRA project for repo"}
    log.info("resolved deployment", extra={**extra, "repo": dep.repo, "commit": dep.commit, "images": len(dep.images)})
    return {"status": "RESOLVED", "deployment": dep.to_dict()}


def wait_handler(event, ctx):
    dep = Deployment.from_dict(event["deployment"])
    ready = inspector.scan_ready(_client("inspector2"), dep.images)
    log.info("scan status", extra={"executionId": dep.execution_id, "ready": ready})
    return {"ready": ready}


def _pom_fetcher(dep: Deployment):
    codecommit = _client("codecommit")

    def fetch(path: str) -> str | None:
        try:
            resp = codecommit.get_file(repositoryName=dep.repo, commitSpecifier=dep.commit, filePath=path)
        except ClientError as e:
            if e.response["Error"]["Code"] in _MISSING_FILE_ERRORS:
                return None
            raise
        return resp["fileContent"].decode("utf-8", errors="replace")

    return fetch


def build_report(dep: Deployment, settings: Settings, cfg: Config) -> Report:
    findings = inspector.list_findings(_client("inspector2"), dep.images)
    project = load_project(_pom_fetcher(dep), cfg.pom_path_for(dep.repo))
    return analyze(dep, findings, project, MavenRepo(settings.maven_repo_url))


def analyze_handler(event, ctx):
    settings = Settings.from_env()
    dep = Deployment.from_dict(event["deployment"])
    report = build_report(dep, settings, load_config(_client("ssm"), settings.config_parameter))
    key = f"reports/{dep.execution_id}.json"
    _client("s3").put_object(Bucket=settings.report_bucket, Key=key, Body=json.dumps(report.to_dict()).encode(),
                             ContentType="application/json")
    total = report.counts()["total"]
    log.info("analyzed", extra={"executionId": dep.execution_id, "findings": total,
                                "suggestions": len(report.suggestions), "pomMissing": report.pom_missing})
    return {"reportRef": {"bucket": settings.report_bucket, "key": key}, "findings": total}


def publish(plan: TicketPlan, existing: dict | None, client: JiraClient, cfg: Config, project: str,
            repo: str) -> str | None:
    """Apply a ticket plan. Returns the key of the ticket involved, if any."""
    key = existing["key"] if existing else None
    priority = cfg.priority_map.get(plan.priority_severity) if plan.priority_severity else None
    if plan.action == "create":
        return client.create_issue(project, cfg.issue_type, plan.summary, plan.description, priority, repo)
    # Comment before description: the description records the new state, so if a step fails in between and is
    # retried, the comment is written again rather than lost.
    if plan.action in ("update", "close"):
        if plan.comment:
            client.add_comment(key, plan.comment)
        if plan.description:
            client.update_issue(key, plan.summary, plan.description, priority)
    if plan.action == "close":
        if not client.transition(key, cfg.done_transition):
            log.warning("transition not available; ticket left open", extra={"issueKey": key,
                                                                             "transition": cfg.done_transition})
    return key


def publish_handler(event, ctx):
    settings = Settings.from_env()
    ref = event["reportRef"]
    report = Report.from_dict(json.loads(_client("s3").get_object(Bucket=ref["bucket"], Key=ref["key"])["Body"].read()))
    dep = report.deployment
    cfg = load_config(_client("ssm"), settings.config_parameter)
    project = cfg.project_for(dep.repo)
    if project is None:
        raise ValueError(f"no JIRA project configured for repo {dep.repo}")
    token = _client("secretsmanager").get_secret_value(SecretId=settings.jira_token_secret_arn)["SecretString"]
    jira = JiraClient(settings.jira_base_url, token.strip())
    existing = jira.find_open_issue(project, dep.repo)
    plan = plan_ticket(report, existing["description"] if existing else None, existing is not None)
    key = publish(plan, existing, jira, cfg, project, dep.repo)
    log.info("published", extra={"executionId": dep.execution_id, "repo": dep.repo, "action": plan.action,
                                 "issueKey": key})
    return {"action": plan.action, "issueKey": key}
