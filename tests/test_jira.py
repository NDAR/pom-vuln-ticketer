import json

import pytest
import requests
import responses

from vuln_ticketer.jira import JiraClient, JiraError, JiraUnavailable

URL = "https://jira.corp"
API = f"{URL}/rest/api/2"


@pytest.fixture
def rsps():
    with responses.RequestsMock() as r:
        yield r


@pytest.fixture
def client():
    return JiraClient(URL, "tok")


def body(rsps, i=0):
    return json.loads(rsps.calls[i].request.body)


def test_bearer_header(rsps, client):
    rsps.add(responses.POST, f"{API}/search", json={"issues": []})
    client.find_open_issue("ORD", "orders-svc")
    assert rsps.calls[0].request.headers["Authorization"] == "Bearer tok"


def test_find_jql(rsps, client):
    rsps.add(responses.POST, f"{API}/search", json={"issues": []})
    assert client.find_open_issue("ORD", "orders-svc") is None
    assert body(rsps)["jql"] == ('project = "ORD" AND labels = "pom-vuln-bot" AND labels = "repo-orders-svc" '
                                 'AND statusCategory != Done ORDER BY created DESC')
    assert body(rsps)["fields"] == ["description"]


def test_find_newest_of_two(rsps, client):
    rsps.add(responses.POST, f"{API}/search", json={"issues": [
        {"key": "ORD-9", "fields": {"description": "d"}}, {"key": "ORD-3", "fields": {"description": "old"}}]})
    assert client.find_open_issue("ORD", "orders-svc") == {"key": "ORD-9", "description": "d"}


def test_find_null_description(rsps, client):
    rsps.add(responses.POST, f"{API}/search", json={"issues": [{"key": "ORD-9", "fields": {"description": None}}]})
    assert client.find_open_issue("ORD", "orders-svc") == {"key": "ORD-9", "description": ""}


def test_create(rsps, client):
    rsps.add(responses.POST, f"{API}/issue", json={"key": "ORD-10"}, status=201)
    assert client.create_issue("ORD", "Task", "sum", "desc", "Highest", "orders-svc") == "ORD-10"
    assert body(rsps)["fields"] == {"project": {"key": "ORD"}, "issuetype": {"name": "Task"}, "summary": "sum",
                                    "description": "desc", "priority": {"name": "Highest"},
                                    "labels": ["pom-vuln-bot", "repo-orders-svc"]}


def test_create_without_priority(rsps, client):
    rsps.add(responses.POST, f"{API}/issue", json={"key": "ORD-10"}, status=201)
    client.create_issue("ORD", "Task", "sum", "desc", None, "orders-svc")
    assert "priority" not in body(rsps)["fields"]


def test_update(rsps, client):
    rsps.add(responses.PUT, f"{API}/issue/ORD-9", status=204)
    client.update_issue("ORD-9", "sum", "desc", "High")
    assert body(rsps) == {"fields": {"summary": "sum", "description": "desc", "priority": {"name": "High"}}}


def test_comment(rsps, client):
    rsps.add(responses.POST, f"{API}/issue/ORD-9/comment", json={"id": "1"}, status=201)
    client.add_comment("ORD-9", "hello")
    assert body(rsps) == {"body": "hello"}


def test_transition_found(rsps, client):
    rsps.add(responses.GET, f"{API}/issue/ORD-9/transitions", json={"transitions": [
        {"id": "21", "name": "In Progress"}, {"id": "31", "name": "Done"}]})
    rsps.add(responses.POST, f"{API}/issue/ORD-9/transitions", status=204)
    assert client.transition("ORD-9", "done") is True
    assert body(rsps, 1) == {"transition": {"id": "31"}}


def test_transition_missing(rsps, client):
    rsps.add(responses.GET, f"{API}/issue/ORD-9/transitions", json={"transitions": [{"id": "21", "name": "In Progress"}]})
    assert client.transition("ORD-9", "Done") is False  # no POST: RequestsMock would fail on an unregistered call


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_4xx_raises_jira_error(rsps, client, status):
    rsps.add(responses.POST, f"{API}/search", json={"errorMessages": ["nope"]}, status=status)
    with pytest.raises(JiraError) as e:
        client.find_open_issue("ORD", "orders-svc")
    assert e.value.status == status and "nope" in str(e.value)


@pytest.mark.parametrize("failure", [500, 503, requests.ConnectionError("down"), requests.Timeout("slow")])
def test_5xx_and_network_raise_unavailable(rsps, client, failure):
    kwargs = {"status": failure} if isinstance(failure, int) else {"body": failure}
    rsps.add(responses.POST, f"{API}/search", **kwargs)
    with pytest.raises(JiraUnavailable):
        client.find_open_issue("ORD", "orders-svc")


def test_trailing_slash(rsps):
    rsps.add(responses.POST, f"{API}/search", json={"issues": []})
    JiraClient("https://jira.corp/", "t").find_open_issue("ORD", "orders-svc")
    assert rsps.calls[0].request.url == "https://jira.corp/rest/api/2/search"
