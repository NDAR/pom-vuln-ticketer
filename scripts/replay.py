"""Run the whole flow from your machine for one past pipeline execution.

Usage: replay.py <pipeline> <execution-id> [--dry-run] [--config-parameter NAME]
                 [--maven-repo-url URL] [--jira-base-url URL] [--jira-token-env VAR]

--dry-run prints the ticket that would be created and never contacts JIRA.
Exit codes: 0 done, 2 pipeline not handled or no JIRA project, 3 Inspector scan not ready.
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from botocore.exceptions import ClientError  # noqa: E402

from vuln_ticketer import handlers  # noqa: E402
from vuln_ticketer.config import Config, Settings, load_config  # noqa: E402
from vuln_ticketer.ticket import plan_ticket  # noqa: E402


def _load_config(settings: Settings, dry_run: bool) -> Config:
    try:
        return load_config(handlers._client("ssm"), settings.config_parameter)
    except ClientError as e:
        if dry_run and e.response["Error"]["Code"] == "ParameterNotFound":
            print(f"(SSM parameter {settings.config_parameter} not found; using defaults for the dry run)", file=sys.stderr)
            return Config()
        raise


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pipeline")
    ap.add_argument("execution_id")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--config-parameter")
    ap.add_argument("--maven-repo-url")
    ap.add_argument("--jira-base-url")
    ap.add_argument("--jira-token-env", default="JIRA_TOKEN")
    args = ap.parse_args(argv)

    token = os.environ.get(args.jira_token_env, "")
    if not args.dry_run:
        if not args.jira_base_url:
            ap.error("--jira-base-url is required unless --dry-run is given")
        if not token:
            ap.error(f"put the JIRA token in the {args.jira_token_env} environment variable, or use --dry-run")

    settings = Settings.from_env()
    settings.config_parameter = args.config_parameter or settings.config_parameter
    settings.maven_repo_url = args.maven_repo_url or settings.maven_repo_url

    dep = handlers.deployment.resolve(
        {"pipeline": args.pipeline, "execution-id": args.execution_id},
        handlers._client("codepipeline"), handlers._client("ecs"), handlers._client("ecr"),
        handlers._client("codedeploy"), set(),
        account_id=handlers._client("sts").get_caller_identity()["Account"])
    if dep is None:
        print("Pipeline execution not handled: it needs a CodeCommit source, an ECS deploy action and an ECR image.",
              file=sys.stderr)
        return 2
    cfg = _load_config(settings, args.dry_run)
    project = cfg.project_for(dep.repo)
    if project is None and not args.dry_run:
        print(f"No JIRA project configured for repo {dep.repo}.", file=sys.stderr)
        return 2
    if not handlers.inspector.scan_ready(handlers._client("inspector2"), dep.images):
        print("Inspector has not finished scanning the deployed image(s); try again in a few minutes.", file=sys.stderr)
        return 3

    report = handlers.build_report(dep, settings, cfg)
    if args.dry_run:
        plan = plan_ticket(report, None, False)
        if plan.action == "none":
            print(f"No critical or high findings for {dep.repo} at {dep.commit[:8]}; no ticket would be created.")
        else:
            print(f"JIRA project: {project or '(none configured)'}\nSummary: {plan.summary}\n\n{plan.description}")
        return 0

    jira = handlers.JiraClient(args.jira_base_url, token)
    existing = jira.find_open_issue(project, dep.repo)
    plan = plan_ticket(report, existing["description"] if existing else None, existing is not None)
    key = handlers.publish(plan, existing, jira, cfg, project, dep.repo)
    print(f"{plan.action} {key or ''}".strip())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
