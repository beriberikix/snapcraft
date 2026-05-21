# -*- Mode:Python; indent-tabs-mode:nil; tab-width:4 -*-
#
# Copyright 2025 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Build-system detectors for ``snapcraft analyze``.

Each detector emits a :class:`~snapcraft.analyze.models.DetectorFinding` with
``category=FindingCategory.BUILD_SYSTEM`` and a ``metadata`` dict containing a
serialised :class:`~snapcraft.analyze.models.BuildSystemInfo`.

Supported ecosystems:
  Go, Python (pip/poetry/uv), Rust, Node.js, CMake, Make, Autotools,
  Meson, Maven, Gradle, .NET
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from snapcraft.analyze.detectors import BaseDetector, registry
from snapcraft.analyze.models import (
    BuildSystemInfo,
    DetectorFinding,
    FindingCategory,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# TOML helpers — tomllib is stdlib ≥ 3.11; fall back to regex for 3.10.
# ---------------------------------------------------------------------------

try:
    import tomllib as _tomllib  # type: ignore[import-not-found]
except ImportError:  # Python 3.10
    _tomllib = None  # type: ignore[assignment]

# Directories that should NOT be checked for missing __init__.py — they are
# either not importable Python packages or are managed by tooling that does
# not require __init__.py.
_PYTHON_SKIP_DIRS = frozenset({
    "tests", "test", "docs", "doc", "examples", "example", "scripts",
    "script", "conf", "config", "data", "assets", "migrations",
    ".git", ".hg", ".venv", "venv", "env", ".tox",
    "dist", "build", "target", "__pycache__", "node_modules",
})


def _parse_toml(path: Path) -> dict:  # type: ignore[type-arg]
    """Parse a TOML file, returning an empty dict on failure."""
    if _tomllib is not None:
        try:
            with path.open("rb") as fh:
                return _tomllib.load(fh)
        except Exception:  # noqa: BLE001
            return {}
    # Fallback: return empty; callers use regex directly on text.
    return {}


def _finding(info: BuildSystemInfo) -> DetectorFinding:
    """Wrap a :class:`BuildSystemInfo` in a :class:`DetectorFinding`."""
    return DetectorFinding(
        category=FindingCategory.BUILD_SYSTEM,
        severity=Severity.INFO,
        description=f"Detected {info.name} project (plugin: {info.plugin})",
        metadata=info.model_dump(),
    )


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


@registry.register
class GolangDetector(BaseDetector):
    """Detect Go projects via ``go.mod``."""

    name = "golang"

    def detect(self) -> list[DetectorFinding]:
        gomod = self._file_exists("go.mod")
        if gomod is None:
            return []

        text = self._read_text(gomod)
        project_name = self._parse_module_name(text)
        go_version = self._parse_go_version(text)

        # The binary name is the last element of the module path.
        binary = project_name.split("/")[-1] if project_name else "app"

        info = BuildSystemInfo(
            name="Go",
            plugin="go",
            version=go_version,
            entry_points=[f"bin/{binary}"],
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _parse_module_name(text: str) -> str:
        m = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
        return m.group(1) if m else ""

    @staticmethod
    def _parse_go_version(text: str) -> str | None:
        m = re.search(r"^go\s+(\S+)", text, re.MULTILINE)
        return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Python — pip / poetry / uv
# ---------------------------------------------------------------------------


@registry.register
class PythonDetector(BaseDetector):
    """Detect Python projects via pyproject.toml, setup.py, or setup.cfg."""

    name = "python"

    def detect(self) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        pyproject = self._file_exists("pyproject.toml")
        if pyproject:
            findings.extend(self._from_pyproject(pyproject))

        if not findings:
            # Fall back to legacy packaging files.
            if self._file_exists("setup.py", "setup.cfg"):
                findings.append(
                    _finding(
                        BuildSystemInfo(
                            name="Python/pip",
                            plugin="python",
                            confidence=0.9,
                        )
                    )
                )

        if findings:
            # Only check for missing __init__.py when we've confirmed this is
            # a Python project.
            findings.extend(self._check_missing_init_py())

        return findings

    def _check_missing_init_py(self) -> list[DetectorFinding]:
        """Flag Python package directories that are missing ``__init__.py``.

        A package directory without ``__init__.py`` can cause import failures
        at runtime, especially when the snap's Python environment differs from
        the development environment.  Modern packaging tools (setuptools ≥ 61,
        hatchling) support "implicit namespace packages" but the behaviour is
        fragile — an explicit ``__init__.py`` is always safer.
        """
        result: list[DetectorFinding] = []
        try:
            for candidate in self._path.iterdir():
                if not candidate.is_dir():
                    continue
                if candidate.name.startswith(".") or candidate.name in _PYTHON_SKIP_DIRS:
                    continue
                # Only flag directories that contain at least one non-init .py file.
                py_files = [
                    f for f in candidate.glob("*.py")
                    if f.name != "__init__.py"
                ]
                if py_files and not (candidate / "__init__.py").exists():
                    result.append(
                        DetectorFinding(
                            category=FindingCategory.CONFINEMENT,
                            severity=Severity.WARNING,
                            description=(
                                f"Python package directory '{candidate.name}/' "
                                "has no __init__.py — the package may not be "
                                "importable at snap runtime."
                            ),
                            file=f"{candidate.name}/__init__.py",
                            metadata={
                                "violation_type": "missing-init-py",
                                "directory": candidate.name,
                            },
                        )
                    )
        except OSError:
            pass
        return result

    def _from_pyproject(self, path: Path) -> list[DetectorFinding]:
        data = _parse_toml(path)
        text = self._read_text(path)

        # Check for a sibling uv.lock file on disk before inspecting content.
        has_uv_lock = (path.parent / "uv.lock").exists()
        plugin, name_suffix = self._detect_plugin(data, text, has_uv_lock=has_uv_lock)
        version = self._detect_version(data)
        entry_points = self._detect_entry_points(data)

        info = BuildSystemInfo(
            name=f"Python/{name_suffix}",
            plugin=plugin,
            version=version,
            entry_points=entry_points,
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _detect_plugin(
        data: dict,  # type: ignore[type-arg]
        text: str,
        *,
        has_uv_lock: bool = False,
    ) -> tuple[str, str]:
        if data:
            build_backend = (
                data.get("build-system", {}).get("build-backend", "") or ""
            )
            if "poetry" in build_backend:
                return "poetry", "Poetry"
            if "hatchling" in build_backend:
                return "python", "pip"
        # Check for uv: sibling uv.lock on disk OR [tool.uv] section in pyproject.toml.
        if has_uv_lock or "[tool.uv]" in text:
            return "uv", "uv"
        if "poetry" in text.lower() and "[tool.poetry]" in text:
            return "poetry", "Poetry"
        return "python", "pip"

    @staticmethod
    def _detect_version(data: dict) -> str | None:  # type: ignore[type-arg]
        """Return the project's release *version*, not the Python interpreter requirement.

        ``requires-python`` is a Python version floor constraint, not a package
        version — it must not be used as the snap ``version`` field.
        """
        if data:
            return (
                data.get("project", {}).get("version")
                or data.get("tool", {}).get("poetry", {}).get("version")
            )
        return None

    @staticmethod
    def _detect_entry_points(data: dict) -> list[str]:  # type: ignore[type-arg]
        if not data:
            return []
        scripts = data.get("project", {}).get("scripts", {})
        if not scripts:
            scripts = (
                data.get("tool", {}).get("poetry", {}).get("scripts", {})
            )
        return [f"bin/{name}" for name in scripts] if scripts else []


# ---------------------------------------------------------------------------
# Rust / Cargo
# ---------------------------------------------------------------------------


@registry.register
class RustDetector(BaseDetector):
    """Detect Rust projects via ``Cargo.toml``."""

    name = "rust"

    def detect(self) -> list[DetectorFinding]:
        cargo = self._file_exists("Cargo.toml")
        if cargo is None:
            return []

        data = _parse_toml(cargo)
        text = self._read_text(cargo)

        pkg_name = ""
        edition = None
        if data:
            pkg = data.get("package", {})
            pkg_name = pkg.get("name", "")
            edition = pkg.get("edition")
        else:
            m = re.search(r'name\s*=\s*"([^"]+)"', text)
            if m:
                pkg_name = m.group(1)

        binary = pkg_name if pkg_name else "app"

        info = BuildSystemInfo(
            name="Rust",
            plugin="rust",
            version=edition,
            entry_points=[f"bin/{binary}"],
            confidence=1.0,
        )
        return [_finding(info)]


# ---------------------------------------------------------------------------
# Node.js / npm
# ---------------------------------------------------------------------------


@registry.register
class NodeDetector(BaseDetector):
    """Detect Node.js projects via ``package.json``."""

    name = "node"

    def detect(self) -> list[DetectorFinding]:
        pkg_json = self._file_exists("package.json")
        if pkg_json is None:
            return []

        try:
            data = json.loads(self._read_text(pkg_json))
        except (json.JSONDecodeError, OSError):
            data = {}

        pkg_name = data.get("name", "app")
        node_version = data.get("engines", {}).get("node")

        info = BuildSystemInfo(
            name="Node.js",
            plugin="npm",
            version=node_version,
            entry_points=[f"bin/{pkg_name}"],
            confidence=1.0,
        )
        return [_finding(info)]


# ---------------------------------------------------------------------------
# CMake
# ---------------------------------------------------------------------------


@registry.register
class CMakeDetector(BaseDetector):
    """Detect CMake projects via ``CMakeLists.txt``."""

    name = "cmake"

    def detect(self) -> list[DetectorFinding]:
        cmake_lists = self._file_exists("CMakeLists.txt")
        if cmake_lists is None:
            return []

        text = self._read_text(cmake_lists)
        project_name = self._parse_project_name(text)
        binary = project_name if project_name else "app"

        info = BuildSystemInfo(
            name="CMake",
            plugin="cmake",
            entry_points=[f"bin/{binary}"],
            build_packages=["gcc", "g++", "cmake", "ninja-build", "pkg-config"],
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _parse_project_name(text: str) -> str:
        m = re.search(r"project\s*\(\s*(\w[\w-]*)", text, re.IGNORECASE)
        return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Make / plain Makefile
# ---------------------------------------------------------------------------


@registry.register
class MakeDetector(BaseDetector):
    """Detect Make projects via a top-level ``Makefile``."""

    name = "make"

    # Filenames that indicate a plain Make project.
    _SENTINEL_FILES = ("Makefile", "GNUmakefile", "makefile")

    def detect(self) -> list[DetectorFinding]:
        # Skip if CMake also present — cmake is a superset.
        if (self._path / "CMakeLists.txt").exists():
            return []
        if self._file_exists(*self._SENTINEL_FILES) is None:
            return []

        info = BuildSystemInfo(
            name="Make",
            plugin="make",
            build_packages=["gcc", "make"],
            confidence=0.8,
        )
        return [_finding(info)]


# ---------------------------------------------------------------------------
# Autotools
# ---------------------------------------------------------------------------


@registry.register
class AutotoolsDetector(BaseDetector):
    """Detect Autotools projects via ``configure.ac`` or ``configure.in``."""

    name = "autotools"

    def detect(self) -> list[DetectorFinding]:
        conf = self._file_exists("configure.ac", "configure.in")
        if conf is None:
            return []

        text = self._read_text(conf)
        project_name = self._parse_ac_init(text)
        binary = project_name if project_name else "app"

        info = BuildSystemInfo(
            name="Autotools",
            plugin="autotools",
            entry_points=[f"bin/{binary}"],
            build_packages=["gcc", "make", "autoconf", "automake", "libtool", "pkg-config"],
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _parse_ac_init(text: str) -> str:
        m = re.search(r"AC_INIT\s*\(\s*\[?([^\],\)]+)\]?", text)
        if m:
            return m.group(1).strip().strip("[]").lower().replace(" ", "-")
        return ""


# ---------------------------------------------------------------------------
# Meson
# ---------------------------------------------------------------------------


@registry.register
class MesonDetector(BaseDetector):
    """Detect Meson projects via ``meson.build``."""

    name = "meson"

    def detect(self) -> list[DetectorFinding]:
        meson_build = self._file_exists("meson.build")
        if meson_build is None:
            return []

        text = self._read_text(meson_build)
        project_name = self._parse_project_name(text)
        binary = project_name if project_name else "app"

        info = BuildSystemInfo(
            name="Meson",
            plugin="meson",
            entry_points=[f"bin/{binary}"],
            build_packages=["meson", "ninja-build", "pkg-config"],
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _parse_project_name(text: str) -> str:
        m = re.search(r"project\s*\(\s*'([^']+)'", text)
        if m:
            return m.group(1).lower()
        m = re.search(r'project\s*\(\s*"([^"]+)"', text)
        return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


@registry.register
class MavenDetector(BaseDetector):
    """Detect Maven projects via ``pom.xml``."""

    name = "maven"

    def detect(self) -> list[DetectorFinding]:
        pom = self._file_exists("pom.xml")
        if pom is None:
            return []

        artifact_id = self._parse_artifact_id(pom)
        binary = artifact_id if artifact_id else "app"

        info = BuildSystemInfo(
            name="Java/Maven",
            plugin="maven",
            entry_points=[f"bin/{binary}"],
            stage_packages=["default-jre-headless"],
            confidence=1.0,
        )
        return [_finding(info)]

    def _parse_artifact_id(self, path: Path) -> str:
        text = self._read_text(path)
        try:
            root = ET.fromstring(text)  # noqa: S314 — pom.xml is developer-authored, not untrusted external input
            # Remove namespace prefix if present.
            ns = re.match(r"\{[^}]+\}", root.tag)
            prefix = ns.group(0) if ns else ""
            node = root.find(f"{prefix}artifactId")
            if node is not None and node.text:
                return node.text.strip()
        except ET.ParseError:
            pass
        m = re.search(r"<artifactId>([^<]+)</artifactId>", text)
        return m.group(1).strip() if m else ""


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------


@registry.register
class GradleDetector(BaseDetector):
    """Detect Gradle projects via ``build.gradle`` or ``build.gradle.kts``."""

    name = "gradle"

    def detect(self) -> list[DetectorFinding]:
        build_file = self._file_exists("build.gradle", "build.gradle.kts")
        if build_file is None:
            return []

        text = self._read_text(build_file)
        main_class = self._parse_main_class(text)

        info = BuildSystemInfo(
            name="Java/Gradle",
            plugin="gradle",
            entry_points=[f"bin/{main_class.split('.')[-1].lower()}"] if main_class else [],
            stage_packages=["default-jre-headless"],
            confidence=1.0,
        )
        return [_finding(info)]

    @staticmethod
    def _parse_main_class(text: str) -> str:
        m = re.search(r"mainClass\s*[=:]\s*[\"']([^\"']+)[\"']", text)
        return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------


@registry.register
class DotNetDetector(BaseDetector):
    """Detect .NET projects via ``*.csproj`` or ``*.sln`` files."""

    name = "dotnet"

    def detect(self) -> list[DetectorFinding]:
        csproj_files = self._find_files("*.csproj")
        sln_files = self._find_files("*.sln")

        if not csproj_files and not sln_files:
            return []

        assembly_name = ""
        if csproj_files:
            assembly_name = self._parse_assembly_name(csproj_files[0])

        binary = assembly_name if assembly_name else "app"

        info = BuildSystemInfo(
            name=".NET",
            plugin="dotnet",
            entry_points=[f"bin/{binary}"],
            confidence=1.0,
        )
        return [_finding(info)]

    def _parse_assembly_name(self, path: Path) -> str:
        text = self._read_text(path)
        m = re.search(r"<AssemblyName>([^<]+)</AssemblyName>", text)
        if m:
            return m.group(1).strip()
        # Fall back to the file stem.
        return path.stem
