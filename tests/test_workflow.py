import json
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent


class _Loader(yaml.SafeLoader):
    """Reads a CloudFormation template, keeping intrinsic functions (!Ref, !Sub, ...) as plain values."""


def _intrinsic(loader, suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {suffix: loader.construct_sequence(node, deep=True)}
    return {suffix: loader.construct_mapping(node, deep=True)}


_Loader.add_multi_constructor("!", _intrinsic)


def workflow():
    return json.loads((ROOT / "statemachine" / "workflow.asl.json").read_text())


def template():
    return yaml.load((ROOT / "template.yaml").read_text(), Loader=_Loader)


def next_targets(state):
    targets = [state[k] for k in ("Next", "Default") if k in state]
    targets += [c["Next"] for c in state.get("Choices", [])]
    targets += [c["Next"] for c in state.get("Catch", [])]
    return targets


def test_workflow_shape():
    wf = workflow()
    assert wf["StartAt"] == "Resolve"
    assert set(wf["States"]) == {"Resolve", "Resolved?", "Skipped", "InitAttempts", "CheckScan", "ScanReady?",
                                 "WaitForScan", "Increment", "RecordScanTimeout", "ScanTimeout", "Analyze", "Publish",
                                 "Done"}
    for name, state in wf["States"].items():
        for target in next_targets(state):
            assert target in wf["States"], (name, target)
        assert state["Type"] in ("Succeed", "Fail") or state.get("End") or next_targets(state), name


def test_tasks_retry_and_publish_does_not_retry_jira_errors():
    states = workflow()["States"]
    for name in ("Resolve", "CheckScan", "Analyze", "Publish"):
        general = states[name]["Retry"][-1]
        assert general == {"ErrorEquals": ["States.TaskFailed"], "IntervalSeconds": 5, "MaxAttempts": 3, "BackoffRate": 2}
    assert states["Publish"]["Retry"][0] == {"ErrorEquals": ["JiraError"], "MaxAttempts": 0}


def test_task_inputs_match_handlers():
    states = workflow()["States"]
    assert states["CheckScan"]["Parameters"] == {"deployment.$": "$.resolve.deployment"}
    assert states["Analyze"]["Parameters"] == {"deployment.$": "$.resolve.deployment"}
    assert states["Publish"]["Parameters"] == {"reportRef.$": "$.analyze.reportRef"}
    choice = states["Resolved?"]["Choices"][0]
    assert (choice["Variable"], choice["StringEquals"], choice["Next"]) == ("$.resolve.status", "SKIPPED", "Skipped")


def test_scan_loop_is_bounded():
    states = workflow()["States"]
    ready, timeout = states["ScanReady?"]["Choices"]
    assert (ready["Variable"], ready["BooleanEquals"], ready["Next"]) == ("$.scan.ready", True, "Analyze")
    assert (timeout["Variable"], timeout["NumericGreaterThanEqualsPath"]) == ("$.loop.attempt", "$.loop.maxAttempts")
    assert timeout["Next"] == "RecordScanTimeout" and states["RecordScanTimeout"]["Next"] == "ScanTimeout"
    assert states["WaitForScan"]["SecondsPath"] == "$.loop.waitSeconds"
    assert states["ScanReady?"]["Default"] == "WaitForScan" and states["Increment"]["Next"] == "CheckScan"
    assert states["ScanTimeout"]["Comment"] == "SKIPPED_SCAN_TIMEOUT"


def test_template_publish_function_is_in_vpc_with_concurrency_one():
    resources = template()["Resources"]
    publish = resources["PublishFunction"]["Properties"]
    assert publish["ReservedConcurrentExecutions"] == 1 and "VpcConfig" in publish
    assert publish["Handler"] == "vuln_ticketer.handlers.publish_handler"
    for name in ("ResolveFunction", "WaitFunction", "AnalyzeFunction"):
        assert "VpcConfig" not in resources[name]["Properties"], name


def test_template_handlers_exist():
    from vuln_ticketer import handlers

    resources = template()["Resources"]
    for name in ("ResolveFunction", "WaitFunction", "AnalyzeFunction", "PublishFunction"):
        module, func = resources[name]["Properties"]["Handler"].rsplit(".", 1)
        assert module == "vuln_ticketer.handlers" and callable(getattr(handlers, func))


def test_template_rule_pattern():
    pattern = template()["Resources"]["Workflow"]["Properties"]["Events"]["PipelineSucceeded"]["Properties"]["Pattern"]
    assert pattern == {"source": ["aws.codepipeline"], "detail-type": ["CodePipeline Pipeline Execution State Change"],
                       "detail": {"state": ["SUCCEEDED"]}}


def test_template_bucket_is_private_and_expires():
    bucket = template()["Resources"]["ReportBucket"]["Properties"]
    assert all(bucket["PublicAccessBlockConfiguration"].values())
    assert bucket["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"] == 30


def test_scan_timeout_metric_has_an_alarm():
    metric = workflow()["States"]["RecordScanTimeout"]["Parameters"]
    alarm = template()["Resources"]["ScanTimeoutAlarm"]["Properties"]
    assert (alarm["Namespace"], alarm["MetricName"]) == (metric["Namespace"], metric["MetricData"][0]["MetricName"])
    assert "Dimensions" not in alarm and "Dimensions" not in metric["MetricData"][0]  # must match to alarm
