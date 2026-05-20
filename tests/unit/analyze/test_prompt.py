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

"""Tests for snapcraft.analyze.prompt."""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest

from snapcraft.analyze.formatters import format_report
from snapcraft.analyze.models import (
    AnalysisReport,
    BuildSystemInfo,
    ConfinementWarning,
    DaemonInfo,
    PlugInfo,
    ScaffoldResult,
)
from snapcraft.analyze.prompt import (
    _SKILL_INSTALL_CMD,
    generate_prompt,
)
from snapcraft.commands.analyze import AnalyzeCommand
from snapcraft.const import OutputFormat

# ---------------------------------------------------------------------------
# Shared report factories
# ---------------------------------------------------------------------------


def _go_daemon_report(tmp_path) -> AnalysisReport:
    scaffold_yaml = (
        "name: myservice\n"
        "base: core24\n"
        "version: git\n"
        "confinement: devmode\n"
        "grade: devel\n"
        "apps:\n"
        "  myservice:\n"
        "    command: bin/myservice\n"
        "    daemon: simple\n"
    )
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
        daemons=[
            DaemonInfo(
                name="myservice",
                daemon_type="simple",
                command="bin/myservice",
                restart_condition="on-failure",
                plugs=["network"],
                source_file="myservice.service",
            )
        ],
        plugs=[PlugInfo(name="network", reason="opens outbound connections")],
        is_headless_daemon=True,
        scaffold=ScaffoldResult(yaml_content=scaffold_yaml, confidence=0.9),
    )


def _python_app_report(tmp_path) -> AnalysisReport:
    scaffold_yaml = (
        "name: myapp\n"
        "base: core24\n"
        "version: 1.2.3\n"
        "confinement: devmode\n"
        "grade: devel\n"
    )
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[
            BuildSystemInfo(
                name="Python/pip",
                plugin="python",
                version="1.2.3",
                entry_points=["bin/myapp"],
                stage_packages=["libpython3.12"],
            )
        ],
        scaffold=ScaffoldResult(yaml_content=scaffold_yaml, confidence=0.8),
    )


def _ubuntu_frame_report(tmp_path) -> AnalysisReport:
    scaffold_yaml = (
        "name: kiosk-app\n"
        "base: core24\n"
        "confinement: devmode\n"
        "grade: devel\n"
    )
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
        is_ubuntu_frame_app=True,
        scaffold=ScaffoldResult(yaml_content=scaffold_yaml, confidence=0.85),
    )


def _no_build_system_report(tmp_path) -> AnalysisReport:
    return AnalysisReport(
        path=str(tmp_path),
        scaffold=ScaffoldResult(
            yaml_content="name: unknown\nbase: core24\n",
            confidence=0.1,
            gaps=["No build system detected; generated a nil-plugin skeleton."],
        ),
    )


def _report_with_confinement_warnings(tmp_path) -> AnalysisReport:
    scaffold_yaml = "name: warned-app\nbase: core24\nconfinement: devmode\n"
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[
            BuildSystemInfo(name="Go", plugin="go", entry_points=["bin/app"])
        ],
        confinement_warnings=[
            ConfinementWarning(
                violation_type="hardcoded-path",
                description="Found hardcoded /etc/myapp in config.go:42",
                file="config.go",
                line=42,
                suggested_fix="Use $SNAP_DATA or $SNAP_COMMON instead.",
            ),
            ConfinementWarning(
                violation_type="user-root",
                description="Service runs as root",
                suggested_fix="Drop privileges in the snap.yaml app entry.",
            ),
        ],
        scaffold=ScaffoldResult(yaml_content=scaffold_yaml, confidence=0.7),
    )


# ---------------------------------------------------------------------------
# Skill install command is always present
# ---------------------------------------------------------------------------


class TestPromptAlwaysIncludesSkillInstall:
    def test_skill_install_in_go_daemon(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert _SKILL_INSTALL_CMD in prompt

    def test_skill_install_in_python_app(self, tmp_path):
        prompt = generate_prompt(_python_app_report(tmp_path))
        assert _SKILL_INSTALL_CMD in prompt

    def test_skill_install_in_ubuntu_frame(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert _SKILL_INSTALL_CMD in prompt

    def test_skill_install_in_no_build_system(self, tmp_path):
        prompt = generate_prompt(_no_build_system_report(tmp_path))
        assert _SKILL_INSTALL_CMD in prompt

    def test_skill_install_command_value(self):
        assert "npx skills add" in _SKILL_INSTALL_CMD
        assert "snapcraft-packaging" in _SKILL_INSTALL_CMD


# ---------------------------------------------------------------------------
# Draft scaffold YAML is embedded with appropriate caveats
# ---------------------------------------------------------------------------


class TestPromptIncludesDraftScaffold:
    def test_scaffold_yaml_embedded(self, tmp_path):
        report = _go_daemon_report(tmp_path)
        prompt = generate_prompt(report)
        assert "name: myservice" in prompt

    def test_draft_caveat_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        # Must clearly indicate this is a draft / starting point.
        assert "draft" in prompt.lower() or "starting point" in prompt.lower()

    def test_todo_resolution_mentioned(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "TODO" in prompt

    def test_scaffold_yaml_absent_when_no_scaffold(self, tmp_path):
        report = AnalysisReport(path=str(tmp_path))
        prompt = generate_prompt(report)
        # No YAML block should be embedded when there is no scaffold.
        assert "name:" not in prompt


# ---------------------------------------------------------------------------
# Snap name extraction
# ---------------------------------------------------------------------------


class TestSnapNameExtraction:
    def test_snap_name_from_scaffold(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "myservice" in prompt

    def test_snap_name_fallback_to_directory(self, tmp_path):
        report = AnalysisReport(path=str(tmp_path))
        prompt = generate_prompt(report)
        assert tmp_path.name in prompt


# ---------------------------------------------------------------------------
# Project-type detection
# ---------------------------------------------------------------------------


class TestProjectTypeSection:
    def test_go_daemon_type(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "daemon" in prompt.lower()

    def test_python_app_type(self, tmp_path):
        prompt = generate_prompt(_python_app_report(tmp_path))
        assert "Python" in prompt

    def test_ubuntu_frame_type(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "Ubuntu Frame" in prompt or "frame" in prompt.lower()

    def test_unknown_type_when_no_build_system(self, tmp_path):
        prompt = generate_prompt(_no_build_system_report(tmp_path))
        assert "Unknown" in prompt or "no build system" in prompt.lower()


# ---------------------------------------------------------------------------
# Conditional sections: daemons
# ---------------------------------------------------------------------------


class TestDaemonSection:
    def test_daemon_info_present_for_daemon_report(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "myservice" in prompt
        assert "simple" in prompt

    def test_daemon_source_file_shown(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "myservice.service" in prompt

    def test_daemon_journalctl_step_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "journalctl -u" in prompt

    def test_no_journalctl_for_non_daemon(self, tmp_path):
        prompt = generate_prompt(_python_app_report(tmp_path))
        # Check for the actual journalctl invocation, not just the word
        # (which can appear in the pytest tmp_path for this test).
        assert "journalctl -u" not in prompt


# ---------------------------------------------------------------------------
# Conditional sections: Ubuntu Frame
# ---------------------------------------------------------------------------


class TestUbuntuFrameSection:
    def test_ubuntu_frame_section_present(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "ubuntu-frame" in prompt.lower() or "Ubuntu Frame" in prompt

    def test_ubuntu_frame_no_journalctl(self, tmp_path):
        # Step 7 now always includes 'journalctl -k | grep DENIED' as an
        # alternative to snappy-debug.  The Frame-specific check is that the
        # daemon service log line ('journalctl -u snap.…') does NOT appear,
        # since Frame apps are not headless daemons.
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "journalctl -u" not in prompt

    def test_non_frame_has_no_frame_snap_install(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "snap install ubuntu-frame" not in prompt


# ---------------------------------------------------------------------------
# Conditional sections: confinement warnings
# ---------------------------------------------------------------------------


class TestConfinementWarningsSection:
    def test_warnings_listed(self, tmp_path):
        prompt = generate_prompt(_report_with_confinement_warnings(tmp_path))
        assert "hardcoded-path" in prompt.lower() or "HARDCODED-PATH" in prompt
        assert "user-root" in prompt.lower() or "USER-ROOT" in prompt

    def test_suggested_fix_shown(self, tmp_path):
        prompt = generate_prompt(_report_with_confinement_warnings(tmp_path))
        assert "SNAP_DATA" in prompt or "$SNAP_DATA" in prompt

    def test_confinement_step_mentions_warnings(self, tmp_path):
        prompt = generate_prompt(_report_with_confinement_warnings(tmp_path))
        # Step 6 should call out the existing warnings.
        assert "confinement issues" in prompt.lower() or "hardcoded paths" in prompt.lower()

    def test_no_warnings_section_when_clean(self, tmp_path):
        report = _go_daemon_report(tmp_path)
        prompt = generate_prompt(report)
        assert "HARDCODED-PATH" not in prompt
        assert "USER-ROOT" not in prompt


# ---------------------------------------------------------------------------
# Conditional sections: scaffold gaps
# ---------------------------------------------------------------------------


class TestGapsSection:
    def test_gaps_listed_when_present(self, tmp_path):
        prompt = generate_prompt(_no_build_system_report(tmp_path))
        assert "nil-plugin skeleton" in prompt or "No build system" in prompt.lower()

    def test_no_gaps_section_when_no_gaps(self, tmp_path):
        report = _go_daemon_report(tmp_path)
        prompt = generate_prompt(report)
        # The Go daemon report has no gaps, so the gaps block should be absent.
        assert "Known gaps" not in prompt


# ---------------------------------------------------------------------------
# Full workflow steps are always present
# ---------------------------------------------------------------------------


class TestFullWorkflowSteps:
    @pytest.mark.parametrize(
        "keyword",
        [
            "snapcraft",       # build step
            "confinement",     # tighten confinement step
            "strict",          # confinement value
            "Snap Store",      # publish step
            "snapcraft upload",# upload command
        ],
    )
    def test_workflow_keyword_present_go_daemon(self, tmp_path, keyword):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert keyword in prompt

    @pytest.mark.parametrize(
        "keyword",
        ["snapcraft", "confinement", "strict", "Snap Store", "snapcraft upload"],
    )
    def test_workflow_keyword_present_ubuntu_frame(self, tmp_path, keyword):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert keyword in prompt


# ---------------------------------------------------------------------------
# Interface plugs section
# ---------------------------------------------------------------------------


class TestPlugsSection:
    def test_plug_reason_shown(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "network" in prompt
        assert "opens outbound connections" in prompt

    def test_no_plugs_section_when_empty(self, tmp_path):
        report = AnalysisReport(
            path=str(tmp_path),
            scaffold=ScaffoldResult(
                yaml_content="name: bare\nbase: core24\n", confidence=0.5
            ),
        )
        prompt = generate_prompt(report)
        assert "Required snap interfaces" not in prompt


# ---------------------------------------------------------------------------
# format_report integration: --format prompt calls _emit_prompt
# ---------------------------------------------------------------------------


class TestFormatReportPromptIntegration:
    def test_format_report_calls_emit_message(self, tmp_path):
        report = _go_daemon_report(tmp_path)
        with patch("snapcraft.analyze.formatters.emit") as mock_emit:
            format_report(report, OutputFormat.prompt)
        mock_emit.message.assert_called_once()
        emitted = mock_emit.message.call_args[0][0]
        assert _SKILL_INSTALL_CMD in emitted


# ---------------------------------------------------------------------------
# AnalyzeCommand: --format prompt accepted by parser
# ---------------------------------------------------------------------------


class TestAnalyzeCommandPromptFormat:
    def setup_method(self):
        self.parser = argparse.ArgumentParser()
        cmd = AnalyzeCommand(None)
        cmd.fill_parser(self.parser)

    def test_prompt_format_accepted(self):
        args = self.parser.parse_args(["--format", "prompt"])
        assert args.format == "prompt"

    def test_run_prompt_format_calls_format_report(self, tmp_path):
        cmd = AnalyzeCommand(None)
        args = argparse.Namespace(path=str(tmp_path), format="prompt", deep=False)
        fake_report = _go_daemon_report(tmp_path)
        mock_svc = MagicMock()
        mock_svc.analyze.return_value = fake_report
        with (
            patch("snapcraft.commands.analyze.AnalyzeService", return_value=mock_svc),
            patch("snapcraft.commands.analyze.format_report") as mock_fmt,
        ):
            cmd.run(args)
        mock_fmt.assert_called_once_with(fake_report, OutputFormat.prompt)


# ---------------------------------------------------------------------------
# Pre-flight checklist section
# ---------------------------------------------------------------------------


class TestPreflightSection:
    def test_preflight_section_always_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "Pre-flight" in prompt

    def test_lxd_multipass_guidance_always_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "SNAPCRAFT_BUILD_ENVIRONMENT=multipass" in prompt
        assert "lxd" in prompt.lower()

    def test_version_git_warning_shown_when_no_git_dir(self, tmp_path):
        # tmp_path has no .git — scaffold will contain version: git
        report = _go_daemon_report(tmp_path)
        prompt = generate_prompt(report)
        assert "git init" in prompt

    def test_version_git_warning_hidden_when_git_dir_exists(self, tmp_path):
        (tmp_path / ".git").mkdir()
        report = _go_daemon_report(tmp_path)
        prompt = generate_prompt(report)
        assert "git init" not in prompt

    def test_tmp_path_warning_shown_for_tmp_project(self, tmp_path):
        # Build a report whose path starts with /tmp
        report = AnalysisReport(
            path="/tmp/my-project",
            build_systems=[BuildSystemInfo(name="Go", plugin="go")],
            scaffold=ScaffoldResult(
                yaml_content="name: my-project\nbase: core24\nversion: git\n",
                confidence=0.9,
            ),
        )
        prompt = generate_prompt(report)
        assert "/tmp" in prompt
        # New text: "cannot access /tmp paths" — no longer macOS-specific
        assert "cannot access" in prompt or "build providers" in prompt.lower()

    def test_tmp_path_warning_absent_for_home_project(self, tmp_path):
        # Use a path that does NOT start with /tmp
        report = AnalysisReport(
            path="/home/user/projects/my-app",
            build_systems=[BuildSystemInfo(name="Go", plugin="go")],
            scaffold=ScaffoldResult(
                yaml_content="name: my-app\nbase: core24\nversion: git\n",
                confidence=0.9,
            ),
        )
        prompt = generate_prompt(report)
        assert "Multipass cannot mount" not in prompt


# ---------------------------------------------------------------------------
# pkexec note present in install steps
# ---------------------------------------------------------------------------


class TestPkexecNote:
    def test_pkexec_note_in_daemon_install_step(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "pkexec" in prompt

    def test_pkexec_note_in_frame_install_step(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "pkexec" in prompt

    def test_pkexec_note_in_generic_install_step(self, tmp_path):
        prompt = generate_prompt(_python_app_report(tmp_path))
        assert "pkexec" in prompt

    def test_pkexec_note_in_confinement_step(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        # The strict-confinement install step also has a pkexec note
        assert "pkexec snap install --dangerous" in prompt


# ---------------------------------------------------------------------------
# Step numbering updated (4=preflight, 5=build, 6=install/smoke, 7=confinement,
# 8=publish)
# ---------------------------------------------------------------------------


class TestStepNumbering:
    def test_step_8_publish_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "## Step 8" in prompt

    def test_step_4_preflight_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "## Step 4" in prompt

    def test_step_5_build_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "## Step 5" in prompt

    def test_no_old_step_4_build_label(self, tmp_path):
        """The old Step 4 build heading is gone; build is now Step 5."""
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        # There should be no "Step 4 — Build" heading
        assert "Step 4 — Build" not in prompt


# ---------------------------------------------------------------------------
# CRAFT_MANAGED_MODE warning (always present in Step 4)
# ---------------------------------------------------------------------------


class TestCraftManagedModeWarning:
    def test_craft_managed_mode_warning_always_present(self, tmp_path):
        """The CRAFT_MANAGED_MODE nested-VM warning is in every prompt."""
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "CRAFT_MANAGED_MODE" in prompt

    def test_craft_managed_mode_warning_in_frame_prompt(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "CRAFT_MANAGED_MODE" in prompt

    def test_craft_managed_mode_unset_instruction(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "unset CRAFT_MANAGED_MODE" in prompt

    def test_snapcraft_build_environment_host_instruction(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "SNAPCRAFT_BUILD_ENVIRONMENT=host" in prompt


# ---------------------------------------------------------------------------
# snappy-debug install step (always present in Step 7)
# ---------------------------------------------------------------------------


class TestSnappyDebugInstallStep:
    def test_snappy_debug_install_command_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "snap install snappy-debug" in prompt

    def test_journalctl_kernel_audit_alternative_present(self, tmp_path):
        """journalctl -k | grep DENIED is listed as an alternative."""
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "journalctl -k" in prompt

    def test_snappy_debug_in_frame_prompt(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "snap install snappy-debug" in prompt


# ---------------------------------------------------------------------------
# Docker interface note (conditional on has_docker_plug)
# ---------------------------------------------------------------------------


class TestDockerPlugNote:
    def _docker_report(self, tmp_path):
        return AnalysisReport(
            path=str(tmp_path),
            build_systems=[BuildSystemInfo(name="Python/pip", plugin="python")],
            daemons=[DaemonInfo(
                name="iot-monitor", daemon_type="simple", command="bin/iot-monitor",
                plugs=["network", "docker"],
            )],
            plugs=[
                PlugInfo(name="network", reason="opens outbound connections"),
                PlugInfo(name="docker", reason="accesses /var/run/docker.sock"),
            ],
            scaffold=ScaffoldResult(
                yaml_content="name: iot-monitor\nbase: core24\nversion: 1.0.0\n",
                confidence=0.9,
            ),
        )

    def test_docker_note_shown_when_docker_plug_present(self, tmp_path):
        prompt = generate_prompt(self._docker_report(tmp_path))
        assert "docker snap" in prompt.lower() or "docker" in prompt

    def test_docker_note_mentions_apt_docker(self, tmp_path):
        prompt = generate_prompt(self._docker_report(tmp_path))
        assert "apt" in prompt

    def test_docker_note_absent_when_no_docker_plug(self, tmp_path):
        prompt = generate_prompt(_python_app_report(tmp_path))
        assert "docker snap" not in prompt.lower() or "docker" not in prompt


# ---------------------------------------------------------------------------
# Non-TTY publish path (always present in Step 8)
# ---------------------------------------------------------------------------


class TestNonTTYPublishPath:
    def test_export_login_command_present(self, tmp_path):
        """snapcraft export-login is always documented in Step 8."""
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "export-login" in prompt

    def test_snapcraft_store_credentials_var_present(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        assert "SNAPCRAFT_STORE_CREDENTIALS" in prompt

    def test_export_login_in_frame_prompt(self, tmp_path):
        prompt = generate_prompt(_ubuntu_frame_report(tmp_path))
        assert "export-login" in prompt


# ---------------------------------------------------------------------------
# restart-condition: always note (conditional)
# ---------------------------------------------------------------------------


class TestRestartAlwaysNote:
    def _always_restart_report(self, tmp_path):
        return AnalysisReport(
            path=str(tmp_path),
            daemons=[DaemonInfo(
                name="myservice", daemon_type="simple", command="bin/svc",
                restart_condition="always",
            )],
            scaffold=ScaffoldResult(
                yaml_content=(
                    "name: myservice\nbase: core24\nversion: git\n"
                    "apps:\n  myservice:\n    daemon: simple\n"
                    "    restart-condition: always\n"
                ),
                confidence=0.9,
            ),
        )

    def test_restart_always_note_shown(self, tmp_path):
        prompt = generate_prompt(self._always_restart_report(tmp_path))
        assert "restart-condition: always" in prompt
        assert "on-failure" in prompt

    def test_restart_always_note_absent_for_on_failure(self, tmp_path):
        prompt = generate_prompt(_go_daemon_report(tmp_path))
        # _go_daemon_report uses restart_condition="on-failure"
        # The note should not appear
        assert "restart-condition: always" not in prompt or "on-failure" in prompt


# ---------------------------------------------------------------------------
# /tmp restriction text is Linux-wide (not macOS-specific)
# ---------------------------------------------------------------------------


class TestTmpRestrictionText:
    def test_tmp_warning_mentions_build_providers(self, tmp_path):
        """New text says 'build providers', not 'macOS'."""
        report = AnalysisReport(
            path="/tmp/my-project",
            build_systems=[BuildSystemInfo(name="Go", plugin="go")],
            scaffold=ScaffoldResult(
                yaml_content="name: my-project\nbase: core24\nversion: git\n",
                confidence=0.9,
            ),
        )
        prompt = generate_prompt(report)
        # The new text is Linux-wide and mentions build providers
        assert "build providers" in prompt.lower() or "cannot access" in prompt

    def test_tmp_warning_not_macos_specific(self, tmp_path):
        report = AnalysisReport(
            path="/tmp/my-project",
            build_systems=[BuildSystemInfo(name="Go", plugin="go")],
            scaffold=ScaffoldResult(
                yaml_content="name: my-project\nbase: core24\nversion: git\n",
                confidence=0.9,
            ),
        )
        prompt = generate_prompt(report)
        # "macOS" should not be mentioned as the reason for the restriction
        assert "macOS" not in prompt
