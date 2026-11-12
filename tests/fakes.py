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


# --- Maven repository fixtures -------------------------------------------------

BASE = "https://repo1.maven.org/maven2"
BOOT = ("org.springframework.boot", "spring-boot-dependencies")
JACKSON_BOM = ("com.fasterxml.jackson", "jackson-bom")
DATABIND = ("com.fasterxml.jackson.core", "jackson-databind")
SNAKEYAML = ("org.yaml", "snakeyaml")
GUAVA = ("com.google.guava", "guava")

# boot version -> (jackson-bom version, snakeyaml version)
BOOT_VERSIONS = {
    "3.1.5": ("2.15.3", "1.33"),
    "3.2.1": ("2.15.3", "2.2"),
    "3.2.5": ("2.15.4", "2.3"),
    "3.2.12": ("2.15.4", "2.3"),
    "3.3.0": ("2.17.2", "2.3"),
}
BOOT_PUBLISHED = ["3.1.5", "3.2.0-RC1", "3.2.1", "3.2.5", "3.2.12", "3.3.0", "4.0.0"]
JACKSON_BOMS = ["2.15.3", "2.15.4", "2.17.2"]
PUBLISHED = {
    BOOT: BOOT_PUBLISHED,
    JACKSON_BOM: JACKSON_BOMS,
    DATABIND: ["2.15.2", "2.15.3", "2.15.4", "2.16.0", "2.17.2"],
    SNAKEYAML: ["1.33", "2.0", "2.2", "2.3"],
    GUAVA: ["31.1-android", "31.1-jre", "32.0.0-android", "32.0.0-jre", "32.0.1-android", "32.0.1-jre"],
    ("org.apache.commons", "commons-text"): ["1.9", "1.10.0", "1.11.0"],
    ("org.apache.poi", "poi"): ["5.2.2", "5.2.5"],
    ("org.example", "obscure"): ["1.0", "1.1"],
}
_HEAD = '<?xml version="1.0"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0">\n  <modelVersion>4.0.0</modelVersion>\n'


def boot_pom(version: str) -> str:
    jackson, snake = BOOT_VERSIONS[version]
    return f"""{_HEAD}  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>{version}</version>
  <packaging>pom</packaging>
  <properties>
    <jackson-bom.version>{jackson}</jackson-bom.version>
    <snakeyaml.version>{snake}</snakeyaml.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.yaml</groupId>
        <artifactId>snakeyaml</artifactId>
        <version>${{snakeyaml.version}}</version>
      </dependency>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>${{jackson-bom.version}}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


def jackson_bom_pom(version: str) -> str:
    return f"""{_HEAD}  <groupId>com.fasterxml.jackson</groupId>
  <artifactId>jackson-bom</artifactId>
  <version>{version}</version>
  <packaging>pom</packaging>
  <properties>
    <jackson.version.databind>${{project.version}}</jackson.version.databind>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${{jackson.version.databind}}</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
"""


def metadata_xml(group: str, artifact: str, versions: list[str]) -> str:
    items = "".join(f"<version>{v}</version>" for v in versions)
    return (f"<metadata><groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
            f"<versioning><versions>{items}</versions></versioning></metadata>")


def maven_files() -> dict[str, str]:
    """Repository-relative path -> file content for everything the fake repository serves."""
    files = {}
    for (g, a), versions in PUBLISHED.items():
        files[f"{g.replace('.', '/')}/{a}/maven-metadata.xml"] = metadata_xml(g, a, versions)
    for v in BOOT_VERSIONS:
        files[f"org/springframework/boot/spring-boot-dependencies/{v}/spring-boot-dependencies-{v}.pom"] = boot_pom(v)
    for v in JACKSON_BOMS:
        files[f"com/fasterxml/jackson/jackson-bom/{v}/jackson-bom-{v}.pom"] = jackson_bom_pom(v)
    return files
