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

"""Tests for build-system detectors."""

import json
from pathlib import Path

import pytest

from snapcraft.analyze.detectors.build_systems import (
    AutotoolsDetector,
    CMakeDetector,
    DotNetDetector,
    GolangDetector,
    GradleDetector,
    MakeDetector,
    MavenDetector,
    MesonDetector,
    NodeDetector,
    PythonDetector,
    RustDetector,
)
from snapcraft.analyze.models import FindingCategory, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detector(cls, tmp_path, deep=False):
    return cls(tmp_path, deep=deep)


def _first_build_system(findings):
    for f in findings:
        if f.category == FindingCategory.BUILD_SYSTEM:
            return f
    return None


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


class TestGolangDetector:
    def test_no_gomod_returns_empty(self, tmp_path):
        assert GolangDetector(tmp_path).detect() == []

    def test_simple_gomod(self, tmp_path):
        (tmp_path / "go.mod").write_text(
            "module github.com/example/myservice\n\ngo 1.22\n"
        )
        findings = GolangDetector(tmp_path).detect()
        assert len(findings) == 1
        f = findings[0]
        assert f.category == FindingCategory.BUILD_SYSTEM
        assert f.metadata["plugin"] == "go"
        assert f.metadata["version"] == "1.22"
        assert "bin/myservice" in f.metadata["entry_points"]

    def test_simple_module_name(self, tmp_path):
        (tmp_path / "go.mod").write_text("module myapp\n\ngo 1.21\n")
        findings = GolangDetector(tmp_path).detect()
        assert findings[0].metadata["entry_points"] == ["bin/myapp"]

    def test_no_go_version(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/tool\n")
        findings = GolangDetector(tmp_path).detect()
        assert findings[0].metadata["version"] is None


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


class TestPythonDetector:
    def test_no_files_returns_empty(self, tmp_path):
        assert PythonDetector(tmp_path).detect() == []

    def test_pyproject_toml_pip(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["setuptools"]\n'
            'build-backend = "setuptools.build_meta"\n'
            "[project]\n"
            'name = "myapp"\n'
            "[project.scripts]\n"
            'myapp = "myapp.cli:main"\n'
        )
        findings = PythonDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "python"
        assert "bin/myapp" in findings[0].metadata["entry_points"]

    def test_pyproject_toml_poetry(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["poetry-core"]\n'
            'build-backend = "poetry.core.masonry.api"\n'
        )
        findings = PythonDetector(tmp_path).detect()
        assert findings[0].metadata["plugin"] == "poetry"
        assert "Poetry" in findings[0].metadata["name"]

    def test_setup_py_fallback(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n")
        findings = PythonDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "python"

    def test_pyproject_wins_over_setup_py(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[build-system]\n")
        (tmp_path / "setup.py").write_text("from setuptools import setup\n")
        findings = PythonDetector(tmp_path).detect()
        # Only one result from pyproject
        assert len(findings) == 1

    def test_version_uses_project_version_not_requires_python(self, tmp_path):
        """version field must reflect the package version, not requires-python."""
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["hatchling"]\n'
            'build-backend = "hatchling.build"\n'
            "[project]\n"
            'name = "iot-monitor"\n'
            'version = "1.0.0"\n'
            'requires-python = ">=3.11"\n'
            "[project.scripts]\n"
            'iot-monitor = "iot_monitor.main:run"\n'
        )
        findings = PythonDetector(tmp_path).detect()
        assert findings[0].metadata["version"] == "1.0.0"

    def test_requires_python_not_used_as_version(self, tmp_path):
        """requires-python constraint must never appear in the version field."""
        (tmp_path / "pyproject.toml").write_text(
            "[project]\n"
            'requires-python = ">=3.10"\n'
        )
        findings = PythonDetector(tmp_path).detect()
        version = findings[0].metadata.get("version")
        assert version != ">=3.10", "requires-python must not be used as snap version"

    def test_poetry_version_extracted(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["poetry-core"]\n'
            'build-backend = "poetry.core.masonry.api"\n'
            "[tool.poetry]\n"
            'name = "myservice"\n'
            'version = "2.3.1"\n'
        )
        findings = PythonDetector(tmp_path).detect()
        assert findings[0].metadata["version"] == "2.3.1"


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


class TestRustDetector:
    def test_no_cargo_returns_empty(self, tmp_path):
        assert RustDetector(tmp_path).detect() == []

    def test_simple_cargo_toml(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            "[package]\n"
            'name = "my-service"\n'
            'version = "0.1.0"\n'
            'edition = "2021"\n'
        )
        findings = RustDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "rust"
        assert "bin/my-service" in findings[0].metadata["entry_points"]

    def test_version_maps_to_edition(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "app"\nedition = "2021"\n'
        )
        findings = RustDetector(tmp_path).detect()
        assert findings[0].metadata["version"] == "2021"


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class TestNodeDetector:
    def test_no_package_json_returns_empty(self, tmp_path):
        assert NodeDetector(tmp_path).detect() == []

    def test_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "my-node-app", "engines": {"node": "20.x"}})
        )
        findings = NodeDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "npm"
        assert findings[0].metadata["version"] == "20.x"

    def test_invalid_json_is_graceful(self, tmp_path):
        (tmp_path / "package.json").write_text("{bad json")
        findings = NodeDetector(tmp_path).detect()
        # Still finds a Node project, just with no version.
        assert findings[0].metadata["plugin"] == "npm"
        assert findings[0].metadata["version"] is None


# ---------------------------------------------------------------------------
# CMake
# ---------------------------------------------------------------------------


class TestCMakeDetector:
    def test_no_cmakelists_returns_empty(self, tmp_path):
        assert CMakeDetector(tmp_path).detect() == []

    def test_cmake_with_project(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\n"
            "project(MyService VERSION 1.0)\n"
        )
        findings = CMakeDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "cmake"
        assert "bin/myservice" in findings[0].metadata["entry_points"]
        assert "cmake" in findings[0].metadata["build_packages"]

    def test_cmake_no_project_directive(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("add_executable(app main.cpp)\n")
        findings = CMakeDetector(tmp_path).detect()
        assert findings[0].metadata["entry_points"] == ["bin/app"]


# ---------------------------------------------------------------------------
# Make
# ---------------------------------------------------------------------------


class TestMakeDetector:
    def test_no_makefile_returns_empty(self, tmp_path):
        assert MakeDetector(tmp_path).detect() == []

    def test_makefile_detected(self, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n\tgcc -o app main.c\n")
        findings = MakeDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "make"

    def test_cmake_takes_precedence(self, tmp_path):
        """CMake present → MakeDetector should be silent."""
        (tmp_path / "CMakeLists.txt").write_text("project(app)\n")
        (tmp_path / "Makefile").write_text("all:\n")
        assert MakeDetector(tmp_path).detect() == []


# ---------------------------------------------------------------------------
# Autotools
# ---------------------------------------------------------------------------


class TestAutotoolsDetector:
    def test_no_configure_ac_returns_empty(self, tmp_path):
        assert AutotoolsDetector(tmp_path).detect() == []

    def test_configure_ac_detected(self, tmp_path):
        (tmp_path / "configure.ac").write_text(
            "AC_INIT([My App], [1.0])\n"
            "AC_PROG_CC\n"
            "AC_OUTPUT\n"
        )
        findings = AutotoolsDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "autotools"
        assert "bin/my-app" in findings[0].metadata["entry_points"]


# ---------------------------------------------------------------------------
# Meson
# ---------------------------------------------------------------------------


class TestMesonDetector:
    def test_no_meson_build_returns_empty(self, tmp_path):
        assert MesonDetector(tmp_path).detect() == []

    def test_meson_build_detected(self, tmp_path):
        (tmp_path / "meson.build").write_text(
            "project('my-sensor', 'c')\nexecutable('sensor', 'main.c')\n"
        )
        findings = MesonDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "meson"
        assert "bin/my-sensor" in findings[0].metadata["entry_points"]


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------


class TestMavenDetector:
    def test_no_pom_xml_returns_empty(self, tmp_path):
        assert MavenDetector(tmp_path).detect() == []

    def test_pom_xml_detected(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            '<?xml version="1.0"?>\n'
            '<project xmlns="http://maven.apache.org/POM/4.0.0">\n'
            "  <modelVersion>4.0.0</modelVersion>\n"
            "  <groupId>com.example</groupId>\n"
            "  <artifactId>my-service</artifactId>\n"
            "  <version>1.0</version>\n"
            "</project>\n"
        )
        findings = MavenDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "maven"
        assert "bin/my-service" in findings[0].metadata["entry_points"]


# ---------------------------------------------------------------------------
# Gradle
# ---------------------------------------------------------------------------


class TestGradleDetector:
    def test_no_build_gradle_returns_empty(self, tmp_path):
        assert GradleDetector(tmp_path).detect() == []

    def test_build_gradle_detected(self, tmp_path):
        (tmp_path / "build.gradle").write_text(
            "plugins { id 'application' }\n"
            "mainClass = 'com.example.Main'\n"
        )
        findings = GradleDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "gradle"

    def test_build_gradle_kts_detected(self, tmp_path):
        (tmp_path / "build.gradle.kts").write_text(
            'mainClass.set("com.example.App")\n'
        )
        findings = GradleDetector(tmp_path).detect()
        assert findings[0].metadata["plugin"] == "gradle"


# ---------------------------------------------------------------------------
# .NET
# ---------------------------------------------------------------------------


class TestDotNetDetector:
    def test_no_csproj_returns_empty(self, tmp_path):
        assert DotNetDetector(tmp_path).detect() == []

    def test_csproj_detected(self, tmp_path):
        (tmp_path / "MyApp.csproj").write_text(
            "<Project Sdk=\"Microsoft.NET.Sdk\">\n"
            "  <PropertyGroup>\n"
            "    <AssemblyName>MyApp</AssemblyName>\n"
            "  </PropertyGroup>\n"
            "</Project>\n"
        )
        findings = DotNetDetector(tmp_path).detect()
        assert len(findings) == 1
        assert findings[0].metadata["plugin"] == "dotnet"
        assert "bin/MyApp" in findings[0].metadata["entry_points"]

    def test_csproj_fallback_to_stem(self, tmp_path):
        (tmp_path / "WebApp.csproj").write_text(
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\" />\n"
        )
        findings = DotNetDetector(tmp_path).detect()
        assert findings[0].metadata["entry_points"] == ["bin/WebApp"]

    def test_sln_detected(self, tmp_path):
        (tmp_path / "Solution.sln").write_text("Microsoft Visual Studio Solution\n")
        findings = DotNetDetector(tmp_path).detect()
        assert findings[0].metadata["plugin"] == "dotnet"
