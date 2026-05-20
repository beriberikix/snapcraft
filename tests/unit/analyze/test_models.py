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

"""Tests for snapcraft.analyze.models."""

import json

import pytest

from snapcraft.analyze.models import (
    AIActionItem,
    AnalysisReport,
    BuildSystemInfo,
    ConfinementWarning,
    DaemonInfo,
    DetectorFinding,
    FindingCategory,
    PlugInfo,
    ScaffoldResult,
    Severity,
)


class TestSeverity:
    def test_str(self):
        assert str(Severity.ERROR) == "error"
        assert str(Severity.WARNING) == "warning"
        assert str(Severity.INFO) == "info"


class TestDetectorFinding:
    def test_minimal(self):
        f = DetectorFinding(
            category=FindingCategory.BUILD_SYSTEM,
            severity=Severity.INFO,
            description="test",
        )
        assert f.category == FindingCategory.BUILD_SYSTEM
        assert f.file is None
        assert f.line is None
        assert f.metadata == {}

    def test_full(self):
        f = DetectorFinding(
            category=FindingCategory.CONFINEMENT,
            severity=Severity.ERROR,
            description="User root found",
            file="Dockerfile",
            line=5,
            metadata={"violation_type": "user-root"},
        )
        assert f.file == "Dockerfile"
        assert f.line == 5
        assert f.metadata["violation_type"] == "user-root"

    def test_json_roundtrip(self):
        f = DetectorFinding(
            category=FindingCategory.DAEMON,
            severity=Severity.INFO,
            description="daemon found",
            metadata={"key": "value"},
        )
        data = f.model_dump()
        assert data["category"] == "daemon"
        # Pydantic v2: model_dump returns enum values as enum instances by default;
        # check serialisation explicitly.
        as_json = json.loads(f.model_dump_json())
        assert as_json["category"] == "daemon"
        assert as_json["severity"] == "info"


class TestBuildSystemInfo:
    def test_defaults(self):
        bs = BuildSystemInfo(name="Go", plugin="go")
        assert bs.build_packages == []
        assert bs.stage_packages == []
        assert bs.entry_points == []
        assert bs.confidence == 1.0

    def test_serialise(self):
        bs = BuildSystemInfo(
            name="Go",
            plugin="go",
            version="1.22",
            entry_points=["bin/myapp"],
            confidence=0.95,
        )
        d = bs.model_dump()
        assert d["name"] == "Go"
        assert d["plugin"] == "go"
        assert d["entry_points"] == ["bin/myapp"]


class TestAIActionItem:
    def test_required_fields(self):
        item = AIActionItem(
            category="hardcoded-path",
            severity=Severity.WARNING,
            description="Hardcoded /etc found",
            suggested_fix="Use layout",
            ai_prompt="Please fix this",
        )
        assert item.reference_url is None
        assert item.file is None

    def test_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            AIActionItem(
                category="x",
                severity=Severity.INFO,
                description="d",
                suggested_fix="f",
                ai_prompt="p",
                unknown_field="oops",
            )


class TestAnalysisReport:
    def test_empty_report(self):
        report = AnalysisReport(path="/tmp/test")
        assert report.build_systems == []
        assert report.daemons == []
        assert report.plugs == []
        assert report.confinement_warnings == []
        assert report.scaffold is None
        assert report.ai_actions == []
        assert not report.is_ubuntu_frame_app
        assert not report.is_headless_daemon

    def test_json_roundtrip(self):
        report = AnalysisReport(
            path="/tmp/test",
            build_systems=[
                BuildSystemInfo(name="Go", plugin="go", entry_points=["bin/app"])
            ],
            daemons=[
                DaemonInfo(name="myapp", daemon_type="simple")
            ],
            plugs=[
                PlugInfo(name="network", reason="test")
            ],
            scaffold=ScaffoldResult(
                yaml_content="name: test\n",
                confidence=0.8,
                gaps=["missing version"],
            ),
        )
        json_str = report.model_dump_json()
        data = json.loads(json_str)
        assert data["path"] == "/tmp/test"
        assert data["build_systems"][0]["name"] == "Go"
        assert data["scaffold"]["confidence"] == 0.8
        assert data["scaffold"]["gaps"] == ["missing version"]

    def test_full_report_serialises_to_valid_json(self):
        """The full report structure can be round-tripped through JSON."""
        report = AnalysisReport(
            path="/repo",
            build_systems=[BuildSystemInfo(name="Rust", plugin="rust")],
            daemons=[DaemonInfo(name="svc", daemon_type="notify", command="bin/svc")],
            plugs=[PlugInfo(name="serial-port", reason="I2C", auto_connect=False)],
            confinement_warnings=[
                ConfinementWarning(
                    violation_type="user-root",
                    description="User root",
                    file="Dockerfile",
                    line=1,
                    suggested_fix="Remove USER root",
                )
            ],
            ai_actions=[
                AIActionItem(
                    category="user-root",
                    severity=Severity.ERROR,
                    description="User root",
                    suggested_fix="Remove",
                    ai_prompt="Fix it",
                )
            ],
            is_headless_daemon=True,
        )
        as_json = json.loads(report.model_dump_json())
        assert as_json["is_headless_daemon"] is True
        assert as_json["confinement_warnings"][0]["violation_type"] == "user-root"
