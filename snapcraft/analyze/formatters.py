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

Two formats are supported:

``table`` (human-readable, default)
    Sections printed to the terminal via ``craft_cli.emit``.

``json``
    Full :class:`~snapcraft.analyze.models.AnalysisReport` serialised as
    indented JSON, emitted as a single ``emit.message()`` call.
"""

from __future__ import annotations

import json

from craft_cli import emit

from snapcraft.analyze.models import AnalysisReport
from snapcraft.const import OutputFormat

_RULE = "─" * 60
_SECTION_RULE = "━" * 60


def format_report(report: AnalysisReport, fmt: OutputFormat) -> None:
    """Emit the analysis report in the requested format.

    :param report: Completed :class:`~snapcraft.analyze.models.AnalysisReport`.
    :param fmt: ``OutputFormat.json`` or ``OutputFormat.table``.
    """
    if fmt == OutputFormat.json:
        _emit_json(report)
    else:
        _emit_table(report)


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------


def _emit_json(report: AnalysisReport) -> None:
    emit.message(json.dumps(report.model_dump(), indent=2, default=str))


# ---------------------------------------------------------------------------
# Human-readable formatter
# ---------------------------------------------------------------------------


def _emit_table(report: AnalysisReport) -> None:
    lines: list[str] = []

    lines.append("")
    lines.append(_SECTION_RULE)
    lines.append(f"  snapcraft analyze: {report.path}")
    lines.append(_SECTION_RULE)

    # ---- Build Systems ----
    lines.append("")
    lines.append("Build System")
    lines.append(_RULE)
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

    # ---- Ubuntu Frame ----
    if report.is_ubuntu_frame_app:
        lines.append("")
        lines.append("Ubuntu Frame (IoT GUI)")
        lines.append(_RULE)
        lines.append("  Graphical application detected.")
        lines.append("  Scaffold uses the gpu-2404 + wayland-launch template.")
        lines.append("  Reference: https://ubuntu.com/frame/docs/24/")

    # ---- Daemons ----
    if report.daemons:
        lines.append("")
        lines.append("Daemons")
        lines.append(_RULE)
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

    # ---- Inferred Interfaces ----
    if report.plugs:
        lines.append("")
        lines.append("Inferred Interface Plugs")
        lines.append(_RULE)
        for plug in report.plugs:
            ac = "auto-connect" if plug.auto_connect else "manual connect"
            lines.append(f"  {plug.name:<25} ({ac})")
            lines.append(f"  {'':25} {plug.reason}")

    # ---- Confinement Warnings ----
    if report.confinement_warnings:
        lines.append("")
        errors = [w for w in report.confinement_warnings if "error" in w.violation_type.lower() or "root" in w.violation_type.lower()]
        warnings = [w for w in report.confinement_warnings if w not in errors]
        count = len(report.confinement_warnings)
        lines.append(f"Confinement Warnings  ({count})")
        lines.append(_RULE)
        for w in report.confinement_warnings:
            location = ""
            if w.file:
                location = f"{w.file}"
                if w.line:
                    location += f":{w.line}"
            tag = w.violation_type.upper()
            lines.append(f"  [{tag}] {location}")
            lines.append(f"  {'':4}{w.description}")
            lines.append(f"  {'':4}Fix: {w.suggested_fix}")
            lines.append("")
    else:
        lines.append("")
        lines.append("Confinement Warnings")
        lines.append(_RULE)
        lines.append("  None detected (shallow scan).")

    # ---- Generated snapcraft.yaml ----
    if report.scaffold:
        confidence_pct = int(report.scaffold.confidence * 100)
        lines.append("")
        lines.append(f"Generated snap/snapcraft.yaml  (confidence: {confidence_pct}%)")
        lines.append(_SECTION_RULE)
        for yaml_line in report.scaffold.yaml_content.splitlines():
            lines.append(f"  {yaml_line}")
        lines.append(_SECTION_RULE)

        if report.scaffold.gaps:
            lines.append("")
            lines.append(f"Scaffold gaps ({len(report.scaffold.gaps)})")
            lines.append(_RULE)
            lines.append(
                "  The following items could not be determined automatically"
                " — search for 'TODO' in the YAML above:"
            )
            for gap in report.scaffold.gaps:
                lines.append(f"  • {gap}")

    # ---- AI Action Items ----
    if report.ai_actions:
        lines.append("")
        lines.append(f"AI Action Items  ({len(report.ai_actions)})")
        lines.append(_RULE)
        lines.append(
            "  The following items require manual or AI-assisted resolution:"
        )
        for item in report.ai_actions:
            sev = item.severity.value.upper()
            lines.append(f"  [{sev}] {item.category}")
            lines.append(f"  {'':6}{item.description}")
            lines.append(f"  {'':6}Fix: {item.suggested_fix}")
            if item.reference_url:
                lines.append(f"  {'':6}Ref: {item.reference_url}")
            lines.append("")

    lines.append("")

    emit.message("\n".join(lines))
