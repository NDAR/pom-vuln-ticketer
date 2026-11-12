"""Maven version ordering (a compact take on Maven's ComparableVersion)."""
from __future__ import annotations

import functools
import re
from typing import Iterable

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")
_RELEASE = 6
_RANKS = {
    "alpha": 1, "pre": 1, "preview": 1, "dev": 1, "ea": 1,
    "beta": 2,
    "milestone": 3,
    "rc": 4, "cr": 4,
    "snapshot": 5,
    "ga": _RELEASE, "final": _RELEASE, "release": _RELEASE,
    "sp": 7,
}
_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}  # only when followed by a digit
_UNKNOWN = 8


def _tokens(v: str) -> list[int | str]:
    raw = _TOKEN.findall(v.lower())
    out: list[int | str] = []
    for i, t in enumerate(raw):
        if t.isdigit():
            out.append(int(t))
        elif t in _SHORT and i + 1 < len(raw) and raw[i + 1].isdigit():
            out.append(_SHORT[t])
        else:
            out.append(t)
    while out and (out[-1] == 0 or (isinstance(out[-1], str) and _RANKS.get(out[-1]) == _RELEASE)):
        out.pop()
    return out


def _sort_key(tok: int | str | None) -> tuple:
    # Numbers sort above every qualifier; a missing token equals 0 / "release".
    if tok is None:
        return (0, _RELEASE, "")
    if isinstance(tok, int):
        return (1, tok, "") if tok else (0, _RELEASE, "")
    rank = _RANKS.get(tok, _UNKNOWN)
    return (0, rank, tok if rank == _UNKNOWN else "")


def compare(a: str, b: str) -> int:
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        ka = _sort_key(ta[i] if i < len(ta) else None)
        kb = _sort_key(tb[i] if i < len(tb) else None)
        if ka != kb:
            return -1 if ka < kb else 1
    return 0


def sort_versions(vs: Iterable[str]) -> list[str]:
    return sorted(vs, key=functools.cmp_to_key(compare))


def is_prerelease(v: str) -> bool:
    return any(isinstance(t, str) and _RANKS.get(t, _UNKNOWN) < _RELEASE for t in _tokens(v))


def flavour(v: str) -> str | None:
    """Trailing qualifier that names a build variant rather than an ordering: "jre", "redhat-1"."""
    matches = list(_TOKEN.finditer(v))
    for i, m in enumerate(matches):
        t = m.group().lower()
        if t.isdigit() or t in _RANKS:
            continue
        if t in _SHORT and i + 1 < len(matches) and matches[i + 1].group().isdigit():
            continue
        return v[m.start():]
    return None


def major(v: str) -> int:
    return minor_line(v)[0]


def minor_line(v: str) -> tuple[int, int]:
    nums: list[int] = []
    for t in _TOKEN.findall(v):
        if not t.isdigit():
            break
        nums.append(int(t))
    nums += [0, 0]
    return (nums[0], nums[1])
