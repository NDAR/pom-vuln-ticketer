"""Test helpers shared across test modules."""
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def read(name: str) -> str:
    return (FIXTURES / "poms" / name).read_text()


def fixture_fetch(name: str):
    """fetch() serving one fixture POM as the repository's root pom.xml."""
    return lambda path: read(name) if path == "pom.xml" else None


def fixture_fetch_dir(dirname: str):
    """fetch() serving a fixture directory as the repository tree."""
    def fetch(path: str):
        f = FIXTURES / "poms" / dirname / path
        return f.read_text() if f.is_file() else None
    return fetch
