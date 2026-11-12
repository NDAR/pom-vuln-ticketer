# pom-vuln-ticketer — Design

Date: 2026-11-11
Status: Draft for review

## Purpose

Java Spring Boot (Maven) services live in AWS CodeCommit and are deployed to
ECS by AWS CodePipeline. AWS Inspector scans the deployed container images, and
most findings come from dependencies declared or managed in the `pom.xml`.

After every successful deployment, this tool creates or refreshes **one open
JIRA ticket per repository** that lists the current Inspector findings and the
concrete POM change that fixes each one.

Success means:

- Engineers get an exact, copy-pasteable POM change per finding.
- Every suggested version exists in the Maven repository.
- Redeploying does not create duplicate tickets or needless notifications.
- The ticket closes itself when the findings are gone.

## Decisions agreed

| Topic | Decision |
|---|---|
| Ticket granularity | One open ticket per repo, refreshed on each deploy |
| Trigger | CodePipeline execution `SUCCEEDED` (EventBridge) |
| Repo and commit | Read from the pipeline execution's source action |
| Image | Read from the ECS service the pipeline deployed |
| JIRA | Data Center / Server, REST API v2, personal access token |
| JIRA project | Per-repo mapping in config, with an optional default |
| JIRA network | Private; the publishing Lambda runs in the VPC |
| Suggestion logic | Rule-based POM analysis, verified against Maven Central (no LLM) |
| Severity | Only CRITICAL and HIGH findings are handled; everything else is ignored |
| Spring Boot | `spring-boot-starter-parent` is the parent in all repos; imported BOM also handled |
| Stack | Python 3.12, AWS SAM, Step Functions; same conventions as `codecommit-pr` |

## Out of scope

- Opening pull requests or changing any POM.
- Gradle projects.
- Running Maven to compute exact transitive dependency paths.
- Reacting to Inspector's continuous rescans between deployments.
- LLM-written explanations.
- MEDIUM, LOW, INFORMATIONAL and UNTRIAGED findings. They are not listed,
  counted, or used to keep a ticket open.

## Architecture

```
CodePipeline "Succeeded" ──EventBridge──▶ Step Functions (Standard workflow)

  1. ResolveDeployment   pipeline execution → repo, branch, commit
                         ECS deploy action → cluster/service → task definition
                         → image URI → ECR image digest
  2. WaitForScan         loop: check Inspector coverage for the digest,
                         wait 2 minutes, up to 15 attempts (~30 minutes)
  3. Analyze             Inspector findings + pom.xml @ commit
                         → classified suggestions (Maven repo lookups)
  4. PublishJira         find open ticket → create, update, or close
     (in VPC, reserved concurrency 1)
```

Step Functions is used because the Inspector scan finishes minutes after the
image push; the workflow waits without holding a Lambda open and gives retries
and an execution history.

### 1. ResolveDeployment

Input: the EventBridge event (`pipeline`, `execution-id`).

- If `PipelineAllowList` is set and the pipeline is not in it, end as `SKIPPED`.
- `codepipeline:GetPipelineExecution` and `ListActionExecutions` give:
  - the CodeCommit source action → repository name, branch, commit ID;
  - the ECS deploy action(s) → cluster and service names. Both the standard
    `ECS` provider and `CodeDeployToECS` (blue/green) are recognised.
- No CodeCommit source or no ECS deploy action → end as `SKIPPED`.
- For each service: `ecs:DescribeServices` → task definition →
  `ecs:DescribeTaskDefinition` → container image URIs. Only ECR images in this
  account are kept. `ecr:DescribeImages` (or the digest in the URI) gives the
  image digest.

Output: `{repo, branch, commit, pipeline, executionId, images: [{service, ecrRepo, digest, uri}]}`.

### 2. WaitForScan

For each image, `inspector2:ListCoverage` filtered by ECR repository and image
digest. The state is ready when every image has scan status `ACTIVE` (scanned).
The state machine loops with a 2-minute `Wait`, up to 15 attempts. On timeout
the execution ends as `SKIPPED_SCAN_TIMEOUT`, emits a metric, and leaves JIRA
untouched.

### 3. Analyze

See "POM analyzer" below. Output is a JSON `Report` (findings, suggestions,
headline, non-POM findings). If the report is larger than the Step Functions
payload limit it is written to an S3 bucket and passed by reference.

### 4. PublishJira

See "JIRA publishing" below. This is the only function attached to the VPC.

## POM analyzer

### Inputs

- `inspector2:ListFindings` filtered by image digest, status `ACTIVE`, type
  `PACKAGE_VULNERABILITY`, severity `CRITICAL` or `HIGH` (filtered in the API
  call). "Findings" everywhere in this document means these findings only. For each vulnerable package: name, installed
  version, `fixedInVersion`, package manager, file path, plus CVE ID, severity
  and title from the finding.
- A finding is a **Java finding** when its package manager is a Java one
  (`JAR`, `POM`, `GRADLE`, …). All others are **non-POM findings**.
- Coordinates: `group:artifact` is taken from the package name when present;
  otherwise the artifact is parsed from the jar file name in the file path and
  the group is resolved from the POM / Boot BOM by artifact ID. The exact
  Inspector field formats are confirmed against a real finding as the first
  implementation task, and recorded as a test fixture.
- POMs: the configured `pomPath` (default `pom.xml`) at the deployed commit via
  `codecommit:GetFile`, plus every POM reachable through `<modules>`.

### POM model (`pom.py`)

Parsed with the standard library XML parser. The model holds, per POM:
parent coordinates, `<properties>`, `<dependencies>`, `<dependencyManagement>`
(including `scope=import` BOMs), and `<modules>`. Property references
(`${x}`) are resolved within the project's own POMs; the model remembers which
property supplied a version so the suggestion can target the property.

### Classification (first match wins, per vulnerable artifact)

1. **Direct with version** — declared in `<dependencies>` with a `<version>`.
   Suggest bumping the version, or the property it references.
2. **Project-managed** — present in the project's own `<dependencyManagement>`.
   Suggest bumping it there (or its property).
3. **Spring Boot-managed** — the project's parent is
   `spring-boot-starter-parent`, or it imports `spring-boot-dependencies`, and
   Boot's BOM (following nested imported BOMs) manages the artifact. Suggest:
   - **Boot upgrade:** the lowest Boot version, in the same minor line, whose
     managed version of the artifact is ≥ the target fixed version; if none in
     that line, the lowest in the next minor lines of the same major.
   - **Property override** (only when Boot is the parent): the Boot version
     property that controls the artifact (for example `jackson-bom.version`)
     set to the target version.
   - If neither is possible, fall through to case 4.
4. **Transitive / unmanaged** — suggest adding a `<dependencyManagement>` entry
   pinning the artifact to the target version, labelled as a transitive pin.

In multi-module projects, the suggestion names the POM file where the
declaration lives; pins and overrides go in the root POM.

### Target version selection

- Candidates come from Inspector's `fixedInVersion` (which may list several).
- Target = the lowest candidate greater than the installed version, preferring
  the installed version's minor line, then major line.
- The target is verified against the artifact's `maven-metadata.xml`. If it is
  not published, the next higher published version is used.
- `fixedInVersion` missing or `NotAvailable` → the finding is listed under
  "No fix available yet".
- Versions are ordered with a small implementation of Maven's
  `ComparableVersion` rules (numeric segments, qualifiers such as `RC`, `M`,
  `SNAPSHOT`, `.RELEASE`/`.Final`). Pre-release versions are never suggested.

### Maven repository access (`maven_repo.py`)

- Base URL is a parameter (default `https://repo1.maven.org/maven2`) so an
  internal mirror can be used.
- Fetches `maven-metadata.xml` (version lists) and BOM POMs
  (`spring-boot-dependencies` and its imports). In-memory cache per invocation.
- If the repository is unreachable, suggestions are still produced from
  Inspector's fixed version, marked **"not verified"**, and the Boot-upgrade
  headline is omitted.

### Roll-up

- Findings on the same artifact merge into one suggestion using the highest
  required target version.
- If one Boot upgrade resolves two or more artifacts, it becomes the headline:
  "Upgrading spring-boot-starter-parent 3.2.1 → 3.2.12 resolves 7 of 9
  findings." Individual suggestions still follow.
- Images from several services of one repo are merged into one report;
  each finding records which service(s) it affects.

## JIRA publishing

### Access

- JIRA Data Center REST API v2 (`/rest/api/2`), `Authorization: Bearer <PAT>`.
- Base URL is a parameter; the PAT is read from Secrets Manager.
- The function runs in the supplied subnets and security group. It reaches
  Secrets Manager and SSM through NAT or VPC endpoints (documented in the
  README as a deployment prerequisite).

### Finding the ticket

JQL: `project = <KEY> AND labels = pom-vuln-bot AND labels = "repo-<repo>" AND statusCategory != Done ORDER BY created DESC`.
If more than one matches, the newest is used and a warning is logged.

### Behaviour

| Open ticket? | Findings? | Action |
|---|---|---|
| No | Yes | Create the issue |
| Yes | Yes, changed | Replace description, update summary, add a change comment |
| Yes | Yes, unchanged | Do nothing (no notification) |
| Yes | None | Comment "All findings resolved as of `<commit>`", then transition |
| No | None | Do nothing |

"None" means no CRITICAL or HIGH findings remain, so a ticket closes even if
lower-severity findings still exist on the image.

- **Summary:** `[<repo>] Dependency vulnerabilities: N findings (X critical, Y high)`.
- **Issue type:** configurable, default `Task`.
- **Priority:** mapped from the highest severity (configurable map; default
  Critical→Highest, High→High).
- **Labels:** `pom-vuln-bot`, `repo-<repo>`.
- **Change comment:** `Deploy <short commit> via <pipeline>: 2 resolved, 1 new, 6 unchanged`
  followed by the new and resolved finding keys.
- **Transition on clean:** configurable transition name, default `Done`. If
  the transition is not available the tool only comments.
- **Change detection:** the description ends with a `{noformat}` block of
  sorted finding keys (`group:artifact@version:CVE`). The next run parses that
  block from the existing ticket. No database is used.
- Reserved concurrency of 1 on this function prevents two concurrent deploys
  from creating two tickets.

### Description layout (JIRA wiki markup)

1. Context line: repo, branch, commit, pipeline, deploy time, image(s).
2. Headline Boot upgrade, when there is one.
3. **Suggested POM changes** — per artifact: current → target version, how it
   was classified, CVEs with severity, POM file and section, and a
   `{code:xml}` snippet.
4. **No fix available yet** — artifact, version, CVEs.
5. **Not fixable in the POM** — counts of critical and high non-Java findings (OS
   packages and similar) and the top five CVEs with package names.
6. The finding-key block.

If the description would exceed JIRA's field limit (32,767 characters), high
findings are collapsed to one line each (critical ones keep their snippets),
then the list is truncated with a count of omitted items.

## Configuration

SAM parameters: `JiraBaseUrl`, `JiraTokenSecretArn`, `ConfigParameterName`,
`VpcSubnetIds`, `VpcSecurityGroupIds`, `MavenRepoUrl`, `PipelineAllowList`
(optional), `AlarmTopicArn` (optional), `ScanWaitSeconds` (120),
`ScanMaxAttempts` (15).

SSM parameter (JSON):

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

A repo that is not listed uses `defaultProject`; if there is no default, the
run is skipped with a log line. The severity filter (CRITICAL and HIGH) is
fixed in code, not configurable.

## Error handling

| Situation | Behaviour |
|---|---|
| Pipeline not allowed, no CodeCommit source, or no ECS deploy | End `SKIPPED` |
| Scan not complete after ~30 minutes | End `SKIPPED_SCAN_TIMEOUT`, metric, JIRA untouched |
| POM not found at `pomPath` | Ticket still produced; every Java finding uses the transitive-pin wording with a note that the POM could not be read |
| Maven repository unreachable | Unverified suggestions, no headline |
| AWS throttling, JIRA 5xx / timeouts | Step Functions retry with backoff (3 attempts) |
| JIRA 4xx (auth, bad project, bad field) | Fail the execution; no retry |
| Any failed execution | CloudWatch alarm on `ExecutionsFailed` → optional SNS topic |

All functions log structured JSON with the pipeline execution ID.

## Code layout

```
pom-vuln-ticketer/
  template.yaml               SAM: state machine, 4 functions, EventBridge rule, IAM, alarm
  src/vuln_ticketer/
    handlers.py               four thin Lambda entry points
    config.py                 SSM config + environment
    deployment.py             pipeline execution → repo, commit, images
    inspector.py              coverage check and findings → Finding objects
    pom.py                    POM parsing and property resolution
    maven_repo.py             repository client, BOM resolution, version comparison
    analyzer.py               classification, target selection, roll-up → Report
    ticket.py                 rendering, finding keys, diff against existing ticket
    jira.py                   JIRA REST client
    models.py                 dataclasses shared between modules
  scripts/replay.py           run the flow for a pipeline execution ID, with --dry-run
  tests/                      pytest suite and fixtures
```

Each module has one job and is testable alone: `analyzer.py` takes plain
`Finding` and POM model objects plus a repository interface and returns a
`Report`; `ticket.py` turns a `Report` and the existing description into a
`TicketPlan` (create / update / close / none) without calling JIRA.

## IAM (least privilege)

- ResolveDeployment: `codepipeline:GetPipelineExecution`,
  `codepipeline:ListActionExecutions`, `codepipeline:GetPipeline`,
  `ecs:DescribeServices`, `ecs:DescribeTaskDefinition`, `ecr:DescribeImages`.
- WaitForScan: `inspector2:ListCoverage`.
- Analyze: `inspector2:ListFindings`, `codecommit:GetFile`,
  `ssm:GetParameter`, S3 put on the report bucket.
- PublishJira: `secretsmanager:GetSecretValue` on the one secret,
  `ssm:GetParameter`, S3 get on the report bucket, VPC networking permissions.

## Testing

- **Unit (pytest):** Maven version comparison; POM parsing and property
  resolution; one fixture POM per classification case (direct, property,
  project-managed, Boot parent, imported Boot BOM, transitive, multi-module);
  Boot BOM resolution against recorded Maven Central responses; target version
  selection; roll-up and headline; ticket rendering, truncation and diffing.
- **Gateways:** AWS calls stubbed with `botocore.stub`; JIRA and Maven HTTP
  stubbed with `responses`.
- **State machine:** the definition is validated in a test, and handler tests
  cover every branch output (`SKIPPED`, not ready, ready, timeout).
- **End to end:** `scripts/replay.py <pipeline> <execution-id> --dry-run`
  runs the real flow against AWS and prints the ticket plan instead of calling
  JIRA. Used to try the tool on existing repos before deployment.
