"""Render the JIRA ticket (wiki markup) and decide what to do with an existing one."""
from __future__ import annotations

import hashlib
import re

from .models import Finding, Report, Suggestion, TicketPlan

MAX_DESCRIPTION = 32767
KEYS_HEADER = "pom-vuln-bot finding keys (do not edit)"
MAX_KEYS_IN_COMMENT = 20
MAX_NO_FIX_LINES = 50
# Marker lines in the key block. They are not findings; they record the state the ticket was written in.
DEGRADED = "#degraded"  # written without the Maven repository or without the POM
RESOLVED = "#resolved"  # no findings left, but the ticket could not (yet) be transitioned
_KEYS_BLOCK = re.compile(r"\{noformat:title=" + re.escape(KEYS_HEADER) + r"\}\n(.*?)\n?\{noformat\}", re.S)
_KIND_LABELS = {
    "direct": "Direct dependency",
    "property": "Version property",
    "managed": "Project dependencyManagement",
    "boot": "Managed by Spring Boot",
    "pin": "Transitive pin",
}


def _esc(text: str) -> str:
    return re.sub(r"([{}|\[\]*])", r"\\\1", text)


def _coords(group: str | None, artifact: str) -> str:
    return _esc(f"{group}:{artifact}" if group else artifact)


def _has_critical(s: Suggestion) -> bool:
    return any(sev == "CRITICAL" for _, sev in s.cves)


def _suggestion_block(s: Suggestion) -> str:
    lines = [
        f"h3. {_coords(s.group, s.artifact)} {_esc(', '.join(s.current))} → {_esc(s.target)}",
        f"File: {_esc(s.pom_file)} · Section: {s.section} · {_KIND_LABELS.get(s.kind, s.kind)}"
        + ("" if s.verified else " (not verified against the Maven repository)"),
        *[f"* {_esc(cve)} ({sev})" for cve, sev in s.cves],
        "{code:xml}", s.snippet, "{code}",
    ]
    if s.override_property:
        lines.append(f"Alternative: set property {_esc(s.override_property)} in <properties>.")
    if s.note:
        lines.append(_esc(s.note))
    return "\n".join(lines) + "\n"


def _suggestion_line(s: Suggestion) -> str:
    return (f"* {_coords(s.group, s.artifact)} {_esc(', '.join(s.current))} → {_esc(s.target)} "
            f"({len(s.cves)} CVEs) — {s.section} in {_esc(s.pom_file)}\n")


def _finding_line(f: Finding) -> str:
    return f"* {_coords(f.group, f.artifact)} {_esc(f.version)} — {_esc(f.cve)} ({f.severity})"


def _keys_block(keys: list[str]) -> str:
    return "{noformat:title=" + KEYS_HEADER + "}\n" + "\n".join(keys) + "\n{noformat}"


def _stored_keys(report: Report) -> list[str]:
    """The keys as written to the ticket: the full list, or one digest line when the list is too long."""
    keys = sorted(report.finding_keys)
    if len(_keys_block(keys)) > MAX_DESCRIPTION // 2:
        keys = ["sha256:" + hashlib.sha256("\n".join(keys).encode()).hexdigest()]
    if report.pom_missing or any(not s.verified for s in report.suggestions):
        keys.append(DEGRADED)
    return keys


def _context_lines(report: Report) -> list[str]:
    d = report.deployment
    images = ", ".join(f"{_esc(i.service)}: {_esc(i.ecr_repo)}@{i.digest[:19]}" for i in d.images)
    return [f"*Repository:* {_esc(d.repo)} | *Branch:* {_esc(d.branch)} | *Commit:* {d.commit[:8]} "
            f"| *Pipeline:* {_esc(d.pipeline)}", f"*Images:* {images}", ""]


def _render_resolved(report: Report) -> str:
    return "\n".join(_context_lines(report) + [
        f"All critical and high findings were resolved as of commit {report.deployment.commit[:8]}.", "",
        _keys_block([RESOLVED])])


def render_description(report: Report) -> str:
    head = _context_lines(report)
    if report.headline:
        head += ["{panel:title=Recommended}", _esc(report.headline), "{panel}", ""]
    if report.pom_missing:
        head += ["{warning}pom.xml could not be read at this commit; changes below are generic pins.{warning}", ""]
    if report.suggestions:
        head += ["h2. Suggested POM changes", ""]

    tail: list[str] = []
    if report.no_fix:
        hidden = len(report.no_fix) - MAX_NO_FIX_LINES
        tail += ["h2. No fix available yet", *[_finding_line(f) for f in report.no_fix[:MAX_NO_FIX_LINES]],
                 *([f"_{hidden} more not shown; see AWS Inspector._"] if hidden > 0 else []), ""]
    if report.non_pom:
        critical = sum(1 for f in report.non_pom if f.severity == "CRITICAL")
        top = sorted(report.non_pom, key=lambda f: (f.severity != "CRITICAL", f.cve))[:5]
        tail += ["h2. Not fixable in the POM",
                 f"{critical} critical, {len(report.non_pom) - critical} high in non-Java packages (base image or OS).",
                 *[_finding_line(f) for f in top], ""]
    tail.append(_keys_block(_stored_keys(report)))

    def assemble(blocks: list[str], omitted: int = 0) -> str:
        note = [f"_{omitted} more suggestions omitted; see AWS Inspector._", ""] if omitted else []
        return "\n".join(head + blocks + note + tail)

    blocks = [_suggestion_block(s) for s in report.suggestions]
    if len(assemble(blocks)) <= MAX_DESCRIPTION:
        return assemble(blocks)
    # Too long: HIGH-only suggestions become one line each, then drop from the end until it fits.
    blocks = [_suggestion_block(s) if _has_critical(s) else _suggestion_line(s) for s in report.suggestions]
    omitted = 0
    while blocks and len(assemble(blocks, omitted)) > MAX_DESCRIPTION:
        blocks.pop()
        omitted += 1
    return assemble(blocks, omitted)


def parse_finding_keys(description: str | None) -> set[str] | None:
    """Finding keys stored in a ticket description; None when the block is absent or unreadable."""
    m = _KEYS_BLOCK.search(description or "")
    if not m:
        return None
    return {line.strip() for line in m.group(1).splitlines() if line.strip()}


def summary_for(report: Report) -> str:
    c = report.counts()
    return (f"[{report.deployment.repo}] Dependency vulnerabilities: {c['total']} findings "
            f"({c['critical']} critical, {c['high']} high)")


def _key_list(title: str, keys: list[str]) -> list[str]:
    if not keys:
        return []
    shown = [f"* {_esc(k)}" for k in keys[:MAX_KEYS_IN_COMMENT]]
    more = [f"…and {len(keys) - MAX_KEYS_IN_COMMENT} more"] if len(keys) > MAX_KEYS_IN_COMMENT else []
    return [f"{title}:", *shown, *more]


def plan_ticket(report: Report, existing_description: str | None, has_open_ticket: bool) -> TicketPlan:
    d = report.deployment
    counts = report.counts()
    if counts["total"] == 0:
        if not has_open_ticket:
            return TicketPlan("none")
        if parse_finding_keys(existing_description) == {RESOLVED}:
            return TicketPlan("close")  # already recorded as resolved; only the transition is still outstanding
        return TicketPlan("close", summary=f"[{d.repo}] Dependency vulnerabilities: resolved",
                          description=_render_resolved(report),
                          comment=f"All critical and high findings resolved as of {d.commit[:8]} "
                                  f"(pipeline {d.pipeline}).")

    plan = TicketPlan("create", summary=summary_for(report), description=render_description(report),
                      priority_severity="CRITICAL" if counts["critical"] else "HIGH")
    if not has_open_ticket:
        return plan

    prefix = f"Deploy {d.commit[:8]} via {d.pipeline}: "
    old, new = parse_finding_keys(existing_description), set(_stored_keys(report))
    if old is None:
        plan.action, plan.comment = "update", prefix + "previous ticket state could not be read; description regenerated."
        return plan
    old_keys, new_keys = ({k for k in keys if not k.startswith("#")} for keys in (old, new))
    was_degraded, is_degraded = DEGRADED in old, DEGRADED in new
    if old_keys == new_keys and (was_degraded == is_degraded or is_degraded) and RESOLVED not in old:
        return TicketPlan("none")  # nothing changed, or this run is the worse-informed one: keep the ticket
    added, resolved = sorted(new_keys - old_keys), sorted(old_keys - new_keys)
    lines = [prefix + f"{len(resolved)} resolved, {len(added)} new, {len(old_keys & new_keys)} unchanged",
             *_key_list("New", added), *_key_list("Resolved", resolved)]
    if was_degraded and not is_degraded:
        lines.append("Suggestions regenerated: the previous ticket was produced without the Maven repository "
                     "or the POM.")
    plan.action, plan.comment = "update", "\n".join(lines)
    return plan
