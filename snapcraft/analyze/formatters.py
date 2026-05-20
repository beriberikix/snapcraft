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

"""Output formatters for ``snapcraft analyze``.

Three formats are supported:

``table`` (human-readable, default)
    Sections printed to the terminal via ``craft_cli.emit``.

``json``
    Full :class:`~snapcraft.analyze.models.AnalysisReport` serialised as
    indented JSON, emitted as a single ``emit.message()`` call.

``prompt``
    A self-contained Markdown prompt for any AI coding agent, covering the
    full snap-packaging workflow from build through to publication.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from craft_cli import emit

from snapcraft.analyze.prompt import generate_prompt
from snapcraft.const import OutputFormat

if TYPE_CHECKING:
    from snapcraft.analyze.models import AnalysisReport

_RULE = "─" * 60
_SECTION_RULE = "━" * 60


def format_report(report: AnalysisReport, fmt: OutputFormat) -> None:
    """Emit the analysis report in the requested format.

    :param report: Completed :class:`~snapcraft.analyze.models.AnalysisReport`.
    :param fmt: ``OutputFormat.json`` or ``OutputFormat.table``.
    """
    if fmt == OutputFormat.json:
        _emit_json(report)
    elif fmt == OutputFormat.prompt:
        _emit_prompt(report)
    else:
        _emit_table(report)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


def _emit_json(report: AnalysisReport) -> None:
    emit.message(json.dumps(report.model_dump(), indent=2, default=str))


# ---------------------------------------------------------------------------
# Prompt formatter
# ---------------------------------------------------------------------------


def _emit_prompt(report: AnalysisReport) -> None:
    emit.message(generate_prompt(report))


# ---------------------------------------------------------------------------
# Human-readable formatter — one helper per section
# ---------------------------------------------------------------------------


def _section_build_systems(report: AnalysisReport) -> list[str]:
    lines: list[str] = ["", "Build System", _RULE]
    if report.build_systems:
        for bs in report.build_systems:
            lines.append(f"  Detected : {bs.name}")
            lines.append(f"  Plugin   : {bs.plugin}")
            if bs.version:
                lines.append(f"  Version  : {bs.version}")
            if bs.entry_points:
                lines.append(f"  Commands : {', '.join(bs.entry_points)}")
            if bs.build_packages:
                lines.append(f"  Build pkgs: {', '.join(bs.build_packages)}")
            if bs.stage_packages:
                lines.append(f"  Stage pkgs: {', '.join(bs.stage_packages)}")
    else:
        lines.append("  No build system detected automatically.")
        lines.append("  Add a build file (go.mod, pyproject.toml, CMakeLists.txt, etc.)")
    return lines


def _section_ubuntu_frame(report: AnalysisReport) -> list[str]:
    if not report.is_ubuntu_frame_app:
        return []
    return [
        "",
        "Ubuntu Frame (IoT GUI)",
        _RULE,
        "  Graphical application detected.",
        "  Scaffold uses the gpu-2404 + wayland-launch template.",
        "  Reference: https://ubuntu.com/frame/docs/24/",
    ]


def _section_daemons(report: AnalysisReport) -> list[str]:
    if not report.daemons:
        return []
    lines: list[str] = ["", "Daemons", _RULE]
    for d in report.daemons:
        cmd = d.command or "unknown"
        lines.append(
            f"  {d.name:<20} daemon: {d.daemon_type:<10} "
            f"restart: {d.restart_condition}"
        )
        lines.append(f"  {'':20} command: {cmd}")
        if d.plugs:
            lines.append(f"  {'':20} plugs: {', '.join(d.plugs)}")
        if d.source_file:
            lines.append(f"  {'':20} source: {d.source_file}")
    return lines


def _section_plugs(report: AnalysisReport) -> list[str]:
    if not report.plugs:
        return []
    lines: list[str] = ["", "Inferred Interface Plugs", _RULE]
    for plug in report.plugs:
        ac = "auto-connect" if plug.auto_connect else "manual connect"
        lines.append(f"  {plug.name:<25} ({ac})")
        lines.append(f"  {'':25} {plug.reason}")
    return lines


def _section_confinement_warnings(report: AnalysisReport) -> list[str]:
    if not report.confinement_warnings:
        return ["", "Confinement Warnings", _RULE, "  None detected (shallow scan)."]
    count = len(report.confinement_warnings)
    lines: list[str] = ["", f"Confinement Warnings  ({count})", _RULE]
    for w in report.confinement_warnings:
        location = w.file or ""
        if location and w.line:
            location = f"{location}:{w.line}"
        tag = w.violation_type.upper()
        lines.append(f"  [{tag}] {location}")
        lines.append(f"  {'':4}{w.description}")
        lines.append(f"  {'':4}Fix: {w.suggested_fix}")
        lines.append("")
    return lines


def _section_scaffold(report: AnalysisReport) -> list[str]:
    if not report.scaffold:
        return []
    confidence_pct = int(report.scaffold.confidence * 100)
    lines: list[str] = [
        "",
        f"Generated snap/snapcraft.yaml  (confidence: {confidence_pct}%)",
        _SECTION_RULE,
    ]
    for yaml_line in report.scaffold.yaml_content.splitlines():
        lines.append(f"  {yaml_line}")
    lines.append(_SECTION_RULE)
    if report.scaffold.gaps:
        lines += [
            "",
            f"Scaffold gaps ({len(report.scaffold.gaps)})",
            _RULE,
            "  The following items could not be determined automatically"
            " — search for 'TODO' in the YAML above:",
        ]
        for gap in report.scaffold.gaps:
            lines.append(f"  • {gap}")
    return lines


def _section_ai_actions(report: AnalysisReport) -> list[str]:
    if not report.ai_actions:
        return []
    lines: list[str] = [
        "",
        f"AI Action Items  ({len(report.ai_actions)})",
        _RULE,
        "  The following items require manual or AI-assisted resolution:",
    ]
    for item in report.ai_actions:
        sev = item.severity.value.upper()
        lines.append(f"  [{sev}] {item.category}")
        lines.append(f"  {'':6}{item.description}")
        lines.append(f"  {'':6}Fix: {item.suggested_fix}")
        if item.reference_url:
            lines.append(f"  {'':6}Ref: {item.reference_url}")
        lines.append("")
    return lines


def _emit_table(report: AnalysisReport) -> None:
    lines: list[str] = [
        "",
        _SECTION_RULE,
        f"  snapcraft analyze: {report.path}",
        _SECTION_RULE,
    ]
    lines += _section_build_systems(report)
    lines += _section_ubuntu_frame(report)
    lines += _section_daemons(report)
    lines += _section_plugs(report)
    lines += _section_confinement_warnings(report)
    lines += _section_scaffold(report)
    lines += _section_ai_actions(report)
    lines.append("")
    emit.message("\n".join(lines))
