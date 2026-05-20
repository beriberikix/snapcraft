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

"""Analysis orchestration service for ``snapcraft analyze``."""

from __future__ import annotations

from pathlib import Path

from craft_cli import emit

from snapcraft.analyze.detectors import registry
from snapcraft.analyze.models import (
    AnalysisReport,
    BuildSystemInfo,
    DaemonInfo,
    FindingCategory,
    PlugInfo,
)
from snapcraft.analyze.scaffold import generate_scaffold
from snapcraft.analyze.warnings import build_confinement_warnings

# ---------------------------------------------------------------------------
# Interface plug inference
# ---------------------------------------------------------------------------

# Findings that imply a specific plug.
_PLUG_TRIGGERS: list[tuple[str, str, str, bool]] = [
    # (metadata_key, metadata_value_contains, plug_name, auto_connect)
    ("plug_hint", "network-bind", "network-bind", True),
    ("plug_hint", "network", "network", True),
]

_HARDWARE_PLUG_PATTERNS = {
    "serial-port": "Serial port or UART device detected.",
    "i2c": "I2C bus usage detected.",
    "spi": "SPI bus usage detected.",
    "gpio": "GPIO pin access detected.",
}


def _infer_plug_name(daemon: DaemonInfo) -> list[PlugInfo]:
    """Convert per-daemon plug hints to PlugInfo objects."""
    plug_map = {
        "network": PlugInfo(
            name="network",
            reason="Daemon requires outbound network access.",
            auto_connect=True,
        ),
        "network-bind": PlugInfo(
            name="network-bind",
            reason="Daemon listens on a network port.",
            auto_connect=True,
        ),
        "serial-port": PlugInfo(
            name="serial-port",
            reason="Daemon accesses a serial device.",
            auto_connect=False,
        ),
        "i2c": PlugInfo(
            name="i2c",
            reason="Daemon accesses I2C bus.",
            auto_connect=False,
        ),
        "spi": PlugInfo(
            name="spi",
            reason="Daemon accesses SPI bus.",
            auto_connect=False,
        ),
        "gpio": PlugInfo(
            name="gpio",
            reason="Daemon accesses GPIO pins.",
            auto_connect=False,
        ),
    }
    return [plug_map[p] for p in daemon.plugs if p in plug_map]


class AnalyzeService:
    """Orchestrate the full analysis pipeline for a repository.

    This class is intentionally *not* a craft-application Service subclass
    so that it can be unit-tested without a full application context.
    """

    def analyze(self, path: Path, *, deep: bool = False) -> AnalysisReport:
        """Run the complete analysis pipeline against *path*.

        :param path: Absolute path to the repository root.
        :param deep: When ``True``, perform exhaustive source-file scanning.
        :returns: A fully populated :class:`~snapcraft.analyze.models.AnalysisReport`.
        """
        emit.progress(f"Analysing '{path}'…")

        # 1. Run all detectors.
        emit.progress("Running detectors…")
        raw_findings = registry.run_all(path, deep=deep)
        emit.debug(f"Detectors produced {len(raw_findings)} raw findings.")

        # 2. Aggregate findings into typed structures.
        build_systems = self._collect_build_systems(raw_findings)
        daemons = self._collect_daemons(raw_findings)
        plugs = self._collect_plugs(raw_findings, daemons)
        is_ubuntu_frame = self._detect_ubuntu_frame(raw_findings)
        is_headless_daemon = bool(daemons) and not is_ubuntu_frame

        # 3. Build confinement warnings and initial AI actions.
        emit.progress("Building confinement warnings…")
        confinement_warnings, ai_actions = build_confinement_warnings(
            raw_findings, path, deep=deep
        )

        # 4. Assemble the partial report (scaffold needs it).
        report = AnalysisReport(
            path=str(path),
            build_systems=build_systems,
            daemons=daemons,
            plugs=plugs,
            confinement_warnings=confinement_warnings,
            ai_actions=ai_actions,
            raw_findings=raw_findings,
            is_ubuntu_frame_app=is_ubuntu_frame,
            is_headless_daemon=is_headless_daemon,
        )

        # 5. Generate the snapcraft.yaml scaffold.
        emit.progress("Generating snapcraft.yaml scaffold…")
        scaffold, scaffold_actions = generate_scaffold(report)
        report.scaffold = scaffold
        report.ai_actions.extend(scaffold_actions)

        emit.debug("Analysis complete.")
        return report

    # ------------------------------------------------------------------
    # Private aggregation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_build_systems(
        findings: list,  # list[DetectorFinding]
    ) -> list[BuildSystemInfo]:
        """Extract BuildSystemInfo objects from raw findings."""
        results: list[BuildSystemInfo] = []
        seen_plugins: set[str] = set()

        for f in findings:
            if f.category != FindingCategory.BUILD_SYSTEM:
                continue
            meta = f.metadata
            if "plugin" not in meta:
                continue
            # Deduplicate by plugin (e.g. CMake + Makefile both present).
            plugin = meta["plugin"]
            if plugin in seen_plugins:
                continue
            seen_plugins.add(plugin)

            results.append(BuildSystemInfo(**meta))

        # Sort by confidence descending.
        return sorted(results, key=lambda b: b.confidence, reverse=True)

    @staticmethod
    def _collect_daemons(findings: list) -> list[DaemonInfo]:  # list[DetectorFinding]
        """Extract DaemonInfo objects from raw findings."""
        results: list[DaemonInfo] = []
        seen_names: set[str] = set()

        for f in findings:
            if f.category != FindingCategory.DAEMON:
                continue
            meta = f.metadata
            if "name" not in meta or "daemon_type" not in meta:
                continue
            name = meta["name"]
            if name in seen_names:
                continue
            seen_names.add(name)
            results.append(DaemonInfo(**meta))

        return results

    @staticmethod
    def _collect_plugs(
        findings: list,  # list[DetectorFinding]
        daemons: list[DaemonInfo],
    ) -> list[PlugInfo]:
        """Infer interface plugs from findings and daemon declarations."""
        plug_map: dict[str, PlugInfo] = {}

        # From explicit plug_hint metadata.
        for f in findings:
            hint = f.metadata.get("plug_hint")
            if hint and hint not in plug_map:
                is_hardware = hint in _HARDWARE_PLUG_PATTERNS
                plug_map[hint] = PlugInfo(
                    name=hint,
                    reason=_HARDWARE_PLUG_PATTERNS.get(
                        hint,
                        f"Inferred from detector finding: {f.description}",
                    ),
                    auto_connect=not is_hardware,
                )

        # From daemon plug declarations.
        for daemon in daemons:
            for plug in _infer_plug_name(daemon):
                if plug.name not in plug_map:
                    plug_map[plug.name] = plug

        return list(plug_map.values())

    @staticmethod
    def _detect_ubuntu_frame(findings: list) -> bool:  # list[DetectorFinding]
        """Return True if any finding marks this as an Ubuntu Frame app."""
        return any(
            f.category == FindingCategory.UBUNTU_FRAME
            and f.metadata.get("is_ubuntu_frame_app")
            for f in findings
        )
