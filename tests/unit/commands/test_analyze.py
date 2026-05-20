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

"""Tests for snapcraft analyze command."""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, patch

import pytest
from craft_cli.errors import ArgumentParsingError

from snapcraft.analyze.models import AnalysisReport, BuildSystemInfo, ScaffoldResult
from snapcraft.commands.analyze import AnalyzeCommand
from snapcraft.const import OutputFormat

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_report(tmp_path):
    return AnalysisReport(
        path=str(tmp_path),
        build_systems=[BuildSystemInfo(name="Go", plugin="go", entry_points=["bin/app"])],
        scaffold=ScaffoldResult(
            yaml_content="name: app\nbase: core24\n",
            confidence=0.9,
        ),
    )


@pytest.fixture
def mock_service(fake_report):
    svc = MagicMock()
    svc.analyze.return_value = fake_report
    return svc


# ---------------------------------------------------------------------------
# Command attributes
# ---------------------------------------------------------------------------


class TestAnalyzeCommandAttributes:
    def test_name(self):
        assert AnalyzeCommand.name == "analyze"

    def test_always_load_project_false(self):
        assert AnalyzeCommand.always_load_project is False

    def test_has_overview(self):
        assert (
            "snapcraft analyze" in AnalyzeCommand.overview
            or "repository" in AnalyzeCommand.overview
        )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestAnalyzeCommandParser:
    def setup_method(self):
        self.parser = argparse.ArgumentParser()
        cmd = AnalyzeCommand(None)
        cmd.fill_parser(self.parser)

    def test_path_defaults_to_dot(self):
        args = self.parser.parse_args([])
        assert args.path == "."

    def test_path_can_be_set(self, tmp_path):
        args = self.parser.parse_args([str(tmp_path)])
        assert args.path == str(tmp_path)

    def test_format_defaults_to_table(self):
        args = self.parser.parse_args([])
        assert args.format == "table"

    def test_format_json(self):
        args = self.parser.parse_args(["--format", "json"])
        assert args.format == "json"

    def test_deep_defaults_to_false(self):
        args = self.parser.parse_args([])
        assert args.deep is False

    def test_deep_flag(self):
        args = self.parser.parse_args(["--deep"])
        assert args.deep is True

    def test_invalid_format_rejected(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args(["--format", "xml"])


# ---------------------------------------------------------------------------
# run() method
# ---------------------------------------------------------------------------


class TestAnalyzeCommandRun:
    def _make_args(self, tmp_path, fmt="table", deep=False):
        return argparse.Namespace(
            path=str(tmp_path),
            format=fmt,
            deep=deep,
        )

    def test_run_calls_service_analyze(self, tmp_path, mock_service):
        cmd = AnalyzeCommand(None)
        args = self._make_args(tmp_path)
        with (
            patch("snapcraft.commands.analyze.AnalyzeService", return_value=mock_service),
            patch("snapcraft.commands.analyze.format_report"),
        ):
            cmd.run(args)
        mock_service.analyze.assert_called_once_with(tmp_path.resolve(), deep=False)

    def test_run_passes_deep_flag(self, tmp_path, mock_service):
        cmd = AnalyzeCommand(None)
        args = self._make_args(tmp_path, deep=True)
        with (
            patch("snapcraft.commands.analyze.AnalyzeService", return_value=mock_service),
            patch("snapcraft.commands.analyze.format_report"),
        ):
            cmd.run(args)
        mock_service.analyze.assert_called_once_with(tmp_path.resolve(), deep=True)

    def test_run_passes_format_to_formatter(self, tmp_path, mock_service, fake_report):
        cmd = AnalyzeCommand(None)
        args = self._make_args(tmp_path, fmt="json")
        with (
            patch("snapcraft.commands.analyze.AnalyzeService", return_value=mock_service),
            patch("snapcraft.commands.analyze.format_report") as mock_fmt,
        ):
            cmd.run(args)
        mock_fmt.assert_called_once_with(fake_report, OutputFormat.json)

    def test_run_raises_for_nonexistent_path(self, tmp_path):
        cmd = AnalyzeCommand(None)
        args = argparse.Namespace(
            path=str(tmp_path / "does-not-exist"),
            format="table",
            deep=False,
        )
        with pytest.raises(ArgumentParsingError, match="does not exist"):
            cmd.run(args)

    def test_run_raises_for_file_path(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("hello")
        cmd = AnalyzeCommand(None)
        args = argparse.Namespace(path=str(f), format="table", deep=False)
        with pytest.raises(ArgumentParsingError, match="not a directory"):
            cmd.run(args)
