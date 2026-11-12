"""JIRA Data Center REST v2 client (personal access token as Bearer)."""
from __future__ import annotations

import requests

from .log import get_logger

LABEL = "pom-vuln-bot"
log = get_logger("jira")


class JiraError(Exception):
    """JIRA rejected the request (4xx). Retrying will not help."""

    def __init__(self, status: int, message: str):
        super().__init__(f"JIRA {status}: {message}")
        self.status = status


class JiraUnavailable(Exception):
    """JIRA could not be reached or failed (5xx, timeout). Worth retrying."""


def repo_label(repo: str) -> str:
    return f"repo-{repo}"


class JiraClient:
    def __init__(self, base_url: str, token: str, session: requests.Session | None = None, timeout: float = 15):
        self.api = base_url.rstrip("/") + "/rest/api/2"
        self.session = session or requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
        self.timeout = timeout

    def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        try:
            resp = self.session.request(method, f"{self.api}{path}", json=json_body, timeout=self.timeout)
        except requests.RequestException as e:
            raise JiraUnavailable(str(e)) from e
        if resp.status_code >= 500:
            raise JiraUnavailable(f"JIRA {resp.status_code} for {method} {path}")
        if resp.status_code >= 400:
            raise JiraError(resp.status_code, resp.text[:500])
        return resp.json() if resp.content else {}

    def find_open_issue(self, project: str, repo: str) -> dict | None:
        jql = (f'project = "{project}" AND labels = "{LABEL}" AND labels = "{repo_label(repo)}" '
               "AND statusCategory != Done ORDER BY created DESC")
        issues = self._request("POST", "/search", {"jql": jql, "fields": ["description"], "maxResults": 5}).get("issues", [])
        if not issues:
            return None
        if len(issues) > 1:
            log.warning("more than one open ticket for repo; using the newest",
                        extra={"repo": repo, "using": issues[0]["key"], "others": [i["key"] for i in issues[1:]]})
        return {"key": issues[0]["key"], "description": issues[0].get("fields", {}).get("description") or ""}

    def create_issue(self, project: str, issue_type: str, summary: str, description: str,
                     priority: str | None, repo: str) -> str:
        fields = {"project": {"key": project}, "issuetype": {"name": issue_type}, "summary": summary,
                  "description": description, "labels": [LABEL, repo_label(repo)]}
        if priority:
            fields["priority"] = {"name": priority}
        return self._request("POST", "/issue", {"fields": fields})["key"]

    def update_issue(self, key: str, summary: str, description: str, priority: str | None) -> None:
        fields = {"summary": summary, "description": description}
        if priority:
            fields["priority"] = {"name": priority}
        self._request("PUT", f"/issue/{key}", {"fields": fields})

    def add_comment(self, key: str, body: str) -> None:
        self._request("POST", f"/issue/{key}/comment", {"body": body})

    def transition(self, key: str, name: str) -> bool:
        """Move the issue through the named transition. False when the workflow has no such transition."""
        transitions = self._request("GET", f"/issue/{key}/transitions").get("transitions", [])
        match = next((t for t in transitions if t.get("name", "").lower() == name.lower()), None)
        if not match:
            return False
        self._request("POST", f"/issue/{key}/transitions", {"transition": {"id": match["id"]}})
        return True
