# pom-vuln-ticketer

After every successful AWS CodePipeline deployment of a Spring Boot (Maven)
service to ECS, this tool reads the AWS Inspector findings for the deployed
container image and works out which `pom.xml` change fixes each one. It keeps
**one open JIRA ticket per CodeCommit repository**, refreshed on each deploy
and closed when the findings are gone. Only **CRITICAL and HIGH** findings are
handled.

## How it works

```
CodePipeline "Succeeded" ──EventBridge──▶ Step Functions
  1. Resolve    pipeline execution → repo + commit; ECS service → image digest
  2. CheckScan  wait (2 min × up to 15) until Inspector has scanned the image
  3. Analyze    findings + pom.xml at that commit → suggested POM changes
  4. Publish    create / update / close the repo's JIRA ticket (runs in your VPC)
```

Each vulnerable artifact is classified by where its version is controlled:

| Where the version comes from | Suggested change |
|---|---|
| A `<dependency>` with a literal version | Bump that `<version>` |
| A `<dependency>` whose version is `${property}` | Bump the property |
| The project's own `<dependencyManagement>` | Bump it there |
| Spring Boot (parent or imported BOM) | Upgrade Boot to the lowest release that manages a fixed version; or override Boot's version property |
| Anything else (transitive) | Add a `<dependencyManagement>` pin |

Suggested versions are checked against the Maven repository. If it cannot be
reached, suggestions are still made from Inspector's fixed version and marked
"not verified".

## Ticket behaviour

| Open ticket for the repo? | Critical/high findings? | What happens |
|---|---|---|
| No | Yes | A ticket is created |
| Yes | Yes, changed | Description and summary are replaced; a comment lists what is new and what was resolved |
| Yes | Yes, unchanged | Nothing (no notification) |
| Yes | None | A comment is added and the ticket is transitioned (default `Done`) |
| No | None | Nothing |

Tickets are found by the labels `pom-vuln-bot` and `repo-<repository name>`.
Do not remove those labels, or the block of finding keys at the bottom of the
description; the tool uses them to find the ticket and to work out what changed.

## Prerequisites

- **Inspector** enhanced scanning enabled for ECR in the account and region.
- **Pipelines** with a CodeCommit source action and an ECS deploy action
  (standard `ECS` or blue/green `CodeDeployToECS`).
- **Network:** subnets and a security group from which JIRA is reachable. The
  publishing function runs there and also needs to reach Secrets Manager, SSM
  and S3, through a NAT gateway or VPC endpoints.
- **JIRA personal access token** for a user who can create, edit, comment on
  and transition issues in the mapped projects. Store it in Secrets Manager as
  a plain string secret.
- **Lambda concurrency:** the publishing function reserves a concurrency of 1.
  The account needs spare unreserved concurrency for that.
- AWS credentials and the
  [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html).

## Configuration

Create an SSM parameter (default name `/pom-vuln-ticketer/config`) holding:

```json
{
  "defaultProject": "PLAT",
  "issueType": "Task",
  "doneTransition": "Done",
  "priorityMap": {"CRITICAL": "Highest", "HIGH": "High"},
  "repos": {
    "orders-svc": {"jiraProject": "ORD", "pomPath": "pom.xml"}
  }
}
```

- `repos` maps a CodeCommit repository name to its JIRA project key and,
  optionally, the path of its root POM.
- A repository that is not listed uses `defaultProject`. With no default, its
  deployments are skipped.
- Everything except the project mapping is optional and defaults to the values
  shown.

## Deploy

```bash
sam build
sam deploy --guided --stack-name pom-vuln-ticketer --capabilities CAPABILITY_IAM
```

Parameters: `JiraBaseUrl`, `JiraTokenSecretArn`, `VpcSubnetIds`,
`VpcSecurityGroupIds`, and optionally `ConfigParameterName`, `MavenRepoUrl`
(an internal mirror), `PipelineAllowList` (comma-separated pipeline names;
empty means all), `AlarmTopicArn` (SNS topic for failed runs),
`ScanWaitSeconds`, `ScanMaxAttempts`.

## Try it before deploying

`scripts/replay.py` runs the whole flow from your machine for one past
pipeline execution. With `--dry-run` it prints the ticket instead of calling
JIRA:

```bash
aws codepipeline list-pipeline-executions --pipeline-name <pipeline> --max-items 3
.venv/bin/python scripts/replay.py <pipeline> <execution-id> --dry-run
```

Without `--dry-run` it publishes to JIRA; pass `--jira-base-url` and put the
token in the `JIRA_TOKEN` environment variable.

## Operations

- **Failed runs** raise the `WorkflowFailedAlarm` CloudWatch alarm (and notify
  `AlarmTopicArn` if set). Open the execution in Step Functions to see which
  step failed.
- **Scan not finished in time:** the run ends successfully at `ScanTimeout`
  without touching JIRA, records the `PomVulnTicketer/ScanTimeout` metric and
  raises `ScanTimeoutAlarm`. If this happens on every deploy, look for
  `image scan not ready` in the CheckScan function's log: it shows the scan
  status Inspector reported.
- **Java findings listed under "Not fixable in the POM":** look for
  `inspector findings read` in the Analyze function's log. It lists the
  package managers Inspector reported; any Java one missing from
  `JAVA_MANAGERS` in `src/vuln_ticketer/inspector.py` needs adding.
- **Images in another account's ECR** (shared sidecars, for example) are
  ignored.
- **Skipped runs** (pipeline not in the allow-list, no CodeCommit source, no
  ECS deploy, or no JIRA project for the repo) end at `Skipped`; the reason is
  in the Resolve step's output.
- Logs are JSON, one object per line, and carry the pipeline `executionId`.

## Develop

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
```

| Path | What it is |
|---|---|
| `src/vuln_ticketer/` | Lambda code: one module per responsibility (see the design spec) |
| `statemachine/workflow.asl.json` | Step Functions definition |
| `template.yaml` | SAM template |
| `scripts/replay.py` | Local run and dry run |
| `scripts/probe_inspector.py` | Captures real Inspector records as test fixtures |
| `tests/` | pytest suite |
| `docs/superpowers/` | Design spec and implementation plan |

The Inspector fixtures in `tests/fixtures/` were written from the API
documentation, not captured from a real image. See `tests/fixtures/README.md`
for how to re-capture them and what to check.
