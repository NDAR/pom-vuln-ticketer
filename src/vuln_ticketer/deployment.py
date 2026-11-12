"""Resolve a finished pipeline execution into what was deployed: repo, commit and image digests."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from .models import Deployment, Image

_ECR_URI = re.compile(
    r"^(?P<account>\d{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?/"
    r"(?P<repo>[^:@]+)(?::(?P<tag>[^@]+))?(?:@(?P<digest>sha256:[0-9a-f]+))?$"
)


def _action_executions(codepipeline, pipeline: str, execution_id: str) -> list[dict]:
    details, token = [], None
    while True:
        page = codepipeline.list_action_executions(
            pipelineName=pipeline, filter={"pipelineExecutionId": execution_id},
            **({"nextToken": token} if token else {}))
        details += page.get("actionExecutionDetails", [])
        token = page.get("nextToken")
        if not token:
            return details


def _ecs_services(actions: list[dict], codedeploy) -> list[tuple[str, str]]:
    """(cluster, service) for every ECS deploy action, standard or blue/green."""
    services: list[tuple[str, str]] = []
    for a in actions:
        type_id, config = a["input"]["actionTypeId"], a["input"].get("configuration", {})
        if type_id["category"] != "Deploy":
            continue
        if type_id["provider"] == "ECS" and config.get("ClusterName") and config.get("ServiceName"):
            services.append((config["ClusterName"], config["ServiceName"]))
        elif type_id["provider"] == "CodeDeployToECS":
            group = codedeploy.get_deployment_group(
                applicationName=config["ApplicationName"], deploymentGroupName=config["DeploymentGroupName"])
            services += [(s["clusterName"], s["serviceName"])
                         for s in group["deploymentGroupInfo"].get("ecsServices", [])]
    return services


def _digest(ecr, account: str, repo: str, tag: str | None) -> str | None:
    try:
        resp = ecr.describe_images(registryId=account, repositoryName=repo, imageIds=[{"imageTag": tag or "latest"}])
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ImageNotFoundException", "RepositoryNotFoundException"):
            return None
        raise
    details = resp.get("imageDetails", [])
    return details[0]["imageDigest"] if details else None


def resolve(detail: dict, codepipeline, ecs, ecr, codedeploy, allow_list: set[str]) -> Deployment | None:
    """None when the pipeline is not one this tool handles (not allowed, not CodeCommit, not ECS)."""
    pipeline, execution_id = detail["pipeline"], detail["execution-id"]
    if allow_list and pipeline not in allow_list:
        return None

    actions = _action_executions(codepipeline, pipeline, execution_id)
    source = next((a for a in actions if a["input"]["actionTypeId"]["category"] == "Source"
                   and a["input"]["actionTypeId"]["provider"] == "CodeCommit"), None)
    if source is None:
        return None
    services = _ecs_services(actions, codedeploy)
    if not services:
        return None

    config = source["input"].get("configuration", {})
    commit = source.get("output", {}).get("outputVariables", {}).get("CommitId")
    if not commit:
        execution = codepipeline.get_pipeline_execution(pipelineName=pipeline, pipelineExecutionId=execution_id)
        revisions = execution["pipelineExecution"].get("artifactRevisions", [])
        commit = revisions[0]["revisionId"] if revisions else None
    if not commit or not config.get("RepositoryName"):
        return None

    images: dict[tuple[str, str], Image] = {}
    for cluster, service in services:
        described = ecs.describe_services(cluster=cluster, services=[service]).get("services", [])
        if not described:
            continue
        task_def = ecs.describe_task_definition(taskDefinition=described[0]["taskDefinition"])["taskDefinition"]
        for container in task_def.get("containerDefinitions", []):
            m = _ECR_URI.match(container.get("image", ""))
            if not m:
                continue
            digest = m["digest"] or _digest(ecr, m["account"], m["repo"], m["tag"])
            if digest:
                images.setdefault((m["repo"], digest), Image(service, m["repo"], digest, container["image"]))
    if not images:
        return None
    return Deployment(repo=config["RepositoryName"], branch=config.get("BranchName", ""), commit=commit,
                      pipeline=pipeline, execution_id=execution_id, images=list(images.values()))
