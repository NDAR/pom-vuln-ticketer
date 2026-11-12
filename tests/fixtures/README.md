# Inspector fixtures

**Status: NOT captured from a real image.** The AWS account available during
implementation had no ECR images, so these three files were written from the
documented `inspector2` API shapes. Re-capture them with
`scripts/probe_inspector.py <ecr-repo> <image-digest>` against a deployed
Spring Boot image and correct `src/vuln_ticketer/inspector.py` if any answer
below turns out to be wrong.

Assumptions the code relies on (each to be confirmed by the probe):

a. `vulnerablePackages[].name` for a jar is `group:artifact` (colon separator).
   When the group is absent, the code parses the artifact from the jar file name.
b. Java `packageManager` values: `JAR`, `POM`, `GRADLE`, `POMPROPERTIES`.
c. `fixedInVersion` is a single version string, or `NotAvailable`, or absent.
   Comma- or space-separated lists are also accepted.
d. A completed scan has `scanStatus.statusCode == "ACTIVE"` and
   `scanStatus.reason == "SUCCESSFUL"`.
