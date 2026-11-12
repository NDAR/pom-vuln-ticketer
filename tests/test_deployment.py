import json

import boto3
import pytest
from botocore.stub import Stubber
from fakes import FIXTURES

from vuln_ticketer.deployment import resolve
from vuln_ticketer.models import Image

DETAIL = json.loads((FIXTURES / "events" / "pipeline_succeeded.json").read_text())["detail"]
URI = "111111111111.dkr.ecr.eu-west-1.amazonaws.com/orders-svc:abc123d"
TASK_DEF = "arn:aws:ecs:eu-west-1:111111111111:task-definition/orders:7"
LIST_ACTIONS = {"pipelineName": "orders-pipeline", "filter": {"pipelineExecutionId": "exec-1"}}


def action(category, provider, configuration, output_variables=None):
    return {
        "pipelineExecutionId": "exec-1", "stageName": category, "actionName": f"{category}-{provider}",
        "input": {"actionTypeId": {"category": category, "owner": "AWS", "provider": provider, "version": "1"},
                  "configuration": configuration},
        "output": {"outputVariables": output_variables or {}},
    }


SOURCE = action("Source", "CodeCommit", {"RepositoryName": "orders-svc", "BranchName": "main"}, {"CommitId": "abc123def"})
BUILD = action("Build", "CodeBuild", {"ProjectName": "orders-build"})
DEPLOY = action("Deploy", "ECS", {"ClusterName": "prod", "ServiceName": "orders"})


class Clients:
    def __init__(self):
        kw = dict(region_name="eu-west-1", aws_access_key_id="x", aws_secret_access_key="x")
        self.cp, self.ecs, self.ecr, self.cd = (boto3.client(n, **kw) for n in ("codepipeline", "ecs", "ecr", "codedeploy"))
        self.stubs = {n: Stubber(c) for n, c in (("cp", self.cp), ("ecs", self.ecs), ("ecr", self.ecr), ("cd", self.cd))}
        for s in self.stubs.values():
            s.activate()

    def actions(self, *details, pages=None):
        if pages:
            self.stubs["cp"].add_response("list_action_executions", {"actionExecutionDetails": pages[0], "nextToken": "t"}, LIST_ACTIONS)
            self.stubs["cp"].add_response("list_action_executions", {"actionExecutionDetails": pages[1]}, {**LIST_ACTIONS, "nextToken": "t"})
        else:
            self.stubs["cp"].add_response("list_action_executions", {"actionExecutionDetails": list(details)}, LIST_ACTIONS)

    def service(self, images, cluster="prod", name="orders", task_def=TASK_DEF):
        self.stubs["ecs"].add_response("describe_services", {"services": [{"serviceName": name, "taskDefinition": task_def}]},
                                       {"cluster": cluster, "services": [name]})
        self.stubs["ecs"].add_response("describe_task_definition", {"taskDefinition": {
            "containerDefinitions": [{"name": f"c{i}", "image": img} for i, img in enumerate(images)]}},
            {"taskDefinition": task_def})

    def digest(self, repo="orders-svc", tag="abc123d", digest="sha256:aaa"):
        self.stubs["ecr"].add_response("describe_images", {"imageDetails": [{"imageDigest": digest}]},
                                       {"registryId": "111111111111", "repositoryName": repo, "imageIds": [{"imageTag": tag}]})

    def resolve(self, allow=frozenset()):
        out = resolve(DETAIL, self.cp, self.ecs, self.ecr, self.cd, set(allow))
        for s in self.stubs.values():
            s.assert_no_pending_responses()
        return out


@pytest.fixture
def aws():
    return Clients()


def test_resolves_standard_ecs(aws):
    aws.actions(SOURCE, BUILD, DEPLOY)
    aws.service([URI])
    aws.digest()
    d = aws.resolve()
    assert (d.repo, d.branch, d.commit, d.pipeline, d.execution_id) == ("orders-svc", "main", "abc123def", "orders-pipeline", "exec-1")
    assert d.images == [Image("orders", "orders-svc", "sha256:aaa", URI)]


def test_allow_list_blocks(aws):
    assert aws.resolve({"other"}) is None  # no AWS calls: every stub is empty


def test_allow_list_allows(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service([URI])
    aws.digest()
    assert aws.resolve({"orders-pipeline"}) is not None


def test_no_codecommit_source(aws):
    aws.actions(action("Source", "GitHub", {"Repo": "x"}), DEPLOY)
    assert aws.resolve() is None


def test_no_ecs_deploy(aws):
    aws.actions(SOURCE, action("Deploy", "S3", {"BucketName": "b"}))
    assert aws.resolve() is None


def test_codedeploy_blue_green(aws):
    aws.actions(SOURCE, action("Deploy", "CodeDeployToECS", {"ApplicationName": "app", "DeploymentGroupName": "dg"}))
    aws.stubs["cd"].add_response("get_deployment_group", {"deploymentGroupInfo": {
        "ecsServices": [{"clusterName": "prod", "serviceName": "orders"}]}},
        {"applicationName": "app", "deploymentGroupName": "dg"})
    aws.service([URI])
    aws.digest()
    assert aws.resolve().images[0].service == "orders"


def test_digest_in_uri(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service(["111111111111.dkr.ecr.eu-west-1.amazonaws.com/orders-svc@sha256:bbb"])
    d = aws.resolve()  # describe_images is not called
    assert d.images[0].digest == "sha256:bbb" and d.images[0].ecr_repo == "orders-svc"


def test_untagged_uri_means_latest(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service(["111111111111.dkr.ecr.eu-west-1.amazonaws.com/team/orders-svc"])
    aws.digest(repo="team/orders-svc", tag="latest")
    assert aws.resolve().images[0].ecr_repo == "team/orders-svc"


def test_non_ecr_image_skipped(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service(["public.ecr.aws/datadog/agent:7", URI])
    aws.digest()
    assert [i.ecr_repo for i in aws.resolve().images] == ["orders-svc"]


def test_only_non_ecr_images(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service(["public.ecr.aws/datadog/agent:7"])
    assert aws.resolve() is None


def test_image_missing_in_ecr_is_skipped(aws):
    aws.actions(SOURCE, DEPLOY)
    aws.service([URI])
    aws.stubs["ecr"].add_client_error("describe_images", "ImageNotFoundException")
    assert aws.resolve() is None


def test_two_services_same_image(aws):
    aws.actions(SOURCE, DEPLOY, action("Deploy", "ECS", {"ClusterName": "prod", "ServiceName": "orders-worker"}))
    aws.service([URI])
    aws.digest()
    aws.service([URI], name="orders-worker")
    aws.digest()
    d = aws.resolve()
    assert d.images == [Image("orders", "orders-svc", "sha256:aaa", URI)]


def test_actions_paginate(aws):
    aws.actions(pages=([SOURCE, BUILD], [DEPLOY]))
    aws.service([URI])
    aws.digest()
    assert aws.resolve() is not None


def test_commit_fallback(aws):
    source = action("Source", "CodeCommit", {"RepositoryName": "orders-svc", "BranchName": "main"})
    aws.actions(source, DEPLOY)
    aws.stubs["cp"].add_response("get_pipeline_execution", {"pipelineExecution": {
        "artifactRevisions": [{"name": "SourceArtifact", "revisionId": "fedcba987"}]}},
        {"pipelineName": "orders-pipeline", "pipelineExecutionId": "exec-1"})
    aws.service([URI])
    aws.digest()
    assert aws.resolve().commit == "fedcba987"
