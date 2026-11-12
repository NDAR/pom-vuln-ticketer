import json


def test_logger_emits_json(capsys):
    from vuln_ticketer.log import get_logger

    get_logger("t").info("hello", extra={"executionId": "abc"})
    rec = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rec["level"] == "INFO" and rec["message"] == "hello" and rec["executionId"] == "abc"
