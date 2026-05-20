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

"""``snapcraft analyze`` command.

Analyses a local Git repository and reports on its readiness for packaging
as a snap targeting Ubuntu Core, headless daemons, and Ubuntu Frame (IoT GUI)
applications.

Usage::

    snapcraft analyze [PATH] [--format json] [--deep]

Output formats:
  * ``table`` (default) — human-readable sections in the terminal.
  * ``json``            — full :class:`AnalysisReport` as JSON on stdout;
                          suitable for piping to ``jq`` or a downstream
                          AI migration agent.
  * ``prompt``          — a self-contained Markdown prompt for any AI coding
                          agent covering the full packaging workflow from
                          build through to publication.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any

from craft_application.commands import AppCommand
from craft_cli import emit
from craft_cli.errors import ArgumentParsingError
from typing_extensions import override

from snapcraft.analyze.formatters import format_report
from snapcraft.const import OUTPUT_FORMATS, OutputFormat
from snapcraft.services.analyze import AnalyzeService

if TYPE_CHECKING:
    import argparse


class AnalyzeCommand(AppCommand):
    """Analyse a repository for snap packaging readiness."""

    always_load_project = False
    name = "analyze"
    help_msg = "Analyse a repository's readiness for snap packaging"
    overview = textwrap.dedent(
        """
        Analyse a local repository and report on its readiness for packaging
        as a snap targeting Ubuntu Core, background daemons, or Ubuntu Frame
        (IoT kiosk / digital signage) applications.

        The command inspects build-system configuration files, systemd units,
        Dockerfiles, and (with --deep) source code to produce:

          * Build system identification and recommended snapcraft plugin
          * Daemon / service configuration hints
          * Snap interface (plug) recommendations
          * Strict-confinement warnings (hardcoded paths, USER root, etc.)
          * A best-effort snap/snapcraft.yaml scaffold with TODO markers
          * Structured AI action items (machine-readable via --format json)

        Examples::

            snapcraft analyze .
            snapcraft analyze /path/to/repo
            snapcraft analyze . --format json | jq .ai_actions
            snapcraft analyze . --format prompt
            snapcraft analyze . --deep
        """
    )

    @override
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "path",
            metavar="PATH",
            nargs="?",
            default=".",
            help=(
                "Path to the repository to analyse. "
                "Defaults to the current directory."
            ),
        )
        parser.add_argument(
            "--format",
            metavar="FORMAT",
            default=OutputFormat.table.value,
            choices=sorted(OUTPUT_FORMATS),
            help=(
                "Output format. "
                f"Choices: {', '.join(sorted(OUTPUT_FORMATS))}. "
                "Use 'json' for machine-readable output suitable for AI agents. "
                "Use 'prompt' to generate an AI coding agent prompt for the "
                "full snap packaging workflow. "
                "(default: table)"
            ),
        )
        parser.add_argument(
            "--deep",
            action="store_true",
            default=False,
            help=(
                "Enable exhaustive source-file scanning. "
                "Scans all source files for hardcoded paths, Wayland/EGL "
                "usage, and other confinement issues. "
                "May be slow on large repositories."
            ),
        )

    @override
    def run(self, parsed_args: argparse.Namespace, **kwargs: Any) -> None:
        """Run the analyze command.

        :param parsed_args: Parsed argument namespace.
        :raises ArgumentParsingError: If the target path does not exist.
        """
        target = Path(parsed_args.path).resolve()

        if not target.exists():
            raise ArgumentParsingError(
                f"path {str(target)!r} does not exist"
            )
        if not target.is_dir():
            raise ArgumentParsingError(
                f"path {str(target)!r} is not a directory"
            )

        fmt = OutputFormat(parsed_args.format)
        deep = parsed_args.deep

        if deep:
            emit.progress(
                "Deep scan enabled — scanning all source files.",
                permanent=True,
            )

        service = AnalyzeService()
        report = service.analyze(target, deep=deep)
        format_report(report, fmt)
