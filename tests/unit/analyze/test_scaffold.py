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

"""Tests for the YAML scaffold generator."""

import pytest
import yaml

from snapcraft.analyze.models import (
    AnalysisReport,
    BuildSystemInfo,
    DaemonInfo,
    FindingCategory,
    DetectorFinding,
    PlugInfo,
    Severity,
)
from snapcraft.analyze.scaffold import generate_scaffold


def _go_report(tmp_path) -> AnalysisReport:
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[
            BuildSystemInfo(
                name="Go",
                plugin="go",
                version="1.22",
                entry_points=["bin/myservice"],
            )
        ],
    )


def _daemon_report(tmp_path) -> AnalysisReport:
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[
            BuildSystemInfo(
                name="Go",
                plugin="go",
                entry_points=["bin/myservice"],
            )
        ],
        daemons=[
            DaemonInfo(
                name="myservice",
                daemon_type="simple",
                command="bin/myservice",
                restart_condition="on-failure",
                plugs=["network"],
            )
        ],
        plugs=[PlugInfo(name="network", reason="inferred")],
        is_headless_daemon=True,
    )


def _frame_report(tmp_path) -> AnalysisReport:
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[
            BuildSystemInfo(
                name="Qt5",
                plugin="cmake",
                entry_points=["bin/kiosk"],
                stage_packages=["qtwayland5"],
            )
        ],
        raw_findings=[
            DetectorFinding(
                category=FindingCategory.UBUNTU_FRAME,
                severity=Severity.INFO,
                description="Frame detected",
                metadata={
                    "is_ubuntu_frame_app": True,
                    "toolkit_name": "Qt5",
                    "stage_packages": ["qtwayland5"],
                    "env_vars": {"QT_QPA_PLATFORM": "wayland"},
                },
            )
        ],
        is_ubuntu_frame_app=True,
    )


class TestScaffoldBasics:
    def test_produces_valid_yaml(self, tmp_path):
        report = _go_report(tmp_path)
        result, _ = generate_scaffold(report)
        doc = yaml.safe_load(result.yaml_content)
        assert doc is not None
        assert isinstance(doc, dict)

    def test_base_is_core24(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert doc["base"] == "core24"

    def test_confinement_is_devmode(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert doc["confinement"] == "devmode"

    def test_grade_is_devel(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert doc["grade"] == "devel"

    def test_platforms_present(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert "platforms" in doc
        assert "amd64" in doc["platforms"]

    def test_snap_name_derived_from_entry_point(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert doc["name"] == "myservice"


class TestScaffoldGoProject:
    def test_go_part_has_build_snap(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        parts = doc["parts"]
        assert "myservice" in parts
        part = parts["myservice"]
        assert part["plugin"] == "go"
        assert "go/1.22/stable" in part.get("build-snaps", [])

    def test_app_command_is_entry_point(self, tmp_path):
        result, _ = generate_scaffold(_go_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert doc["apps"]["myservice"]["command"] == "bin/myservice"


class TestScaffoldDaemon:
    def test_daemon_app_entry(self, tmp_path):
        result, _ = generate_scaffold(_daemon_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        app = doc["apps"]["myservice"]
        assert app["daemon"] == "simple"
        assert app["restart-condition"] == "on-failure"

    def test_daemon_plugs_included(self, tmp_path):
        result, _ = generate_scaffold(_daemon_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        plugs = doc["apps"]["myservice"]["plugs"]
        assert "network" in plugs


class TestScaffoldUbuntuFrame:
    def test_gpu_2404_plug_present(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert "gpu-2404" in doc.get("plugs", {})
        assert doc["plugs"]["gpu-2404"]["interface"] == "content"
        assert doc["plugs"]["gpu-2404"]["default-provider"] == "mesa-2404"

    def test_wayland_environment(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        env = doc.get("environment", {})
        assert "XDG_CACHE_HOME" in env
        assert "XKB_CONFIG_ROOT" in env

    def test_layout_has_libdrm(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        layout = doc.get("layout", {})
        assert "/usr/share/libdrm" in layout

    def test_dual_app_entries(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        apps = doc["apps"]
        # Should have both interactive and daemon entries.
        assert "kiosk" in apps or "daemon" in apps
        daemon_entry = apps.get("daemon")
        assert daemon_entry is not None
        assert daemon_entry["daemon"] == "simple"

    def test_gpu_2404_part_present(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert "gpu-2404" in doc["parts"]

    def test_setup_part_present(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        assert "setup" in doc["parts"]

    def test_command_chain_in_apps(self, tmp_path):
        result, _ = generate_scaffold(_frame_report(tmp_path))
        doc = yaml.safe_load(result.yaml_content)
        for _name, app in doc["apps"].items():
            assert "bin/gpu-2404-wrapper" in app.get("command-chain", [])
            assert "bin/wayland-launch" in app.get("command-chain", [])

    def test_no_yaml_anchors_in_output(self, tmp_path):
        """command-chain/plugs/environment lists must be independent copies.

        When the same Python list or dict object is shared between app entries
        PyYAML emits ``&id001`` / ``*id001`` anchors.  The raw YAML text must
        not contain any anchors so that the scaffold is directly copy-pasteable.
        """
        result, _ = generate_scaffold(_frame_report(tmp_path))
        assert "&id" not in result.yaml_content, (
            "YAML anchors (&id…) found in scaffold — "
            "app entries must use independent list/dict copies."
        )


class TestScaffoldConfidence:
    def test_full_project_has_high_confidence(self, tmp_path):
        result, _ = generate_scaffold(_daemon_report(tmp_path))
        assert result.confidence >= 0.8

    def test_empty_project_has_low_confidence(self, tmp_path):
        report = AnalysisReport(path=str(tmp_path))
        result, _ = generate_scaffold(report)
        assert result.confidence < 0.7

    def test_gaps_produce_ai_actions(self, tmp_path):
        report = AnalysisReport(path=str(tmp_path))
        result, ai_actions = generate_scaffold(report)
        assert len(result.gaps) > 0
        assert len(ai_actions) > 0
        # Every gap should have a corresponding AI action.
        assert len(ai_actions) >= len(result.gaps)


class TestScaffoldFallback:
    def test_unknown_project_produces_nil_plugin(self, tmp_path):
        report = AnalysisReport(path=str(tmp_path))
        result, _ = generate_scaffold(report)
        doc = yaml.safe_load(result.yaml_content)
        parts = doc["parts"]
        assert any(p.get("plugin") == "nil" for p in parts.values())

    def test_directory_name_used_for_snap_name(self, tmp_path):
        subdir = tmp_path / "my-cool-service"
        subdir.mkdir()
        report = AnalysisReport(path=str(subdir))
        result, _ = generate_scaffold(report)
        doc = yaml.safe_load(result.yaml_content)
        assert doc["name"] == "my-cool-service"
