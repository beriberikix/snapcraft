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

"""YAML scaffold generator for ``snapcraft analyze``.

Takes a partially-populated :class:`~snapcraft.analyze.models.AnalysisReport`
and produces a best-effort ``snapcraft.yaml``.

Key decisions:
  * ``base: core24`` (always — modern baseline)
  * ``confinement: devmode`` (always — start safe for development)
  * ``grade: devel`` (until confinement is tightened to ``strict``)
  * For Ubuntu Frame apps: applies the gpu-2404 content interface pattern,
    wayland-launch command chain, dual app+daemon entries, and all required
    layouts and environment variables.
  * For headless daemons: applies the standard daemon pattern.
  * For unrecognised projects: produces a minimal skeleton with TODO markers.

Every gap (piece of information the generator could not determine) is
recorded in :attr:`~snapcraft.analyze.models.ScaffoldResult.gaps` and
results in an :class:`~snapcraft.analyze.models.AIActionItem`.
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path
from typing import Any

import yaml

from snapcraft.analyze.models import (
    AIActionItem,
    AnalysisReport,
    ScaffoldResult,
    Severity,
)


def generate_scaffold(report: AnalysisReport) -> tuple[ScaffoldResult, list[AIActionItem]]:
    """Generate a ``snapcraft.yaml`` scaffold from *report*.

    :param report: Fully populated :class:`~snapcraft.analyze.models.AnalysisReport`.
    :returns: A ``(ScaffoldResult, ai_actions)`` pair.  The *ai_actions* list
        contains one item per gap that was encountered.
    """
    generator = _ScaffoldGenerator(report)
    return generator.generate()


class _ScaffoldGenerator:
    """Internal scaffold builder."""

    def __init__(self, report: AnalysisReport) -> None:
        self._report = report
        self._gaps: list[str] = []
        self._ai_actions: list[AIActionItem] = []

    def generate(self) -> tuple[ScaffoldResult, list[AIActionItem]]:
        doc: dict[str, Any] = {}

        self._add_metadata(doc)
        self._add_confinement(doc)
        self._add_platforms(doc)

        if self._report.is_ubuntu_frame_app:
            self._add_ubuntu_frame_plugs(doc)
            self._add_ubuntu_frame_environment(doc)
            self._add_ubuntu_frame_layout(doc)
            self._add_ubuntu_frame_apps(doc)
            self._add_ubuntu_frame_parts(doc)
        else:
            self._add_standard_apps(doc)
            self._add_standard_parts(doc)

        yaml_str = self._dump(doc)
        confidence = self._compute_confidence()

        result = ScaffoldResult(
            yaml_content=yaml_str,
            confidence=confidence,
            gaps=list(self._gaps),
        )
        return result, list(self._ai_actions)

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def _add_metadata(self, doc: dict[str, Any]) -> None:
        path = Path(self._report.path)
        snap_name = self._derive_snap_name()

        doc["name"] = snap_name
        doc["base"] = "core24"
        doc["version"] = self._derive_version()
        doc["summary"] = f"TODO: one-line summary for {snap_name} (max 79 chars)"
        doc["description"] = "TODO: describe what this snap does.\n"
        doc["grade"] = "devel"

    def _derive_snap_name(self) -> str:
        """Infer the snap name from detected build systems or the directory."""
        if self._report.build_systems:
            bs = self._report.build_systems[0]
            if bs.entry_points:
                # "bin/myapp" → "myapp"
                return bs.entry_points[0].split("/")[-1]
        if self._report.daemons:
            return self._report.daemons[0].name
        # Fall back to directory name, sanitised for snap naming rules.
        path_name = Path(self._report.path).name
        sanitised = re.sub(r"[^a-z0-9-]", "-", path_name.lower()).strip("-")
        if not sanitised:
            self._note_gap(
                "snap-name",
                "Could not determine snap name from directory or project files.",
                ai_prompt=(
                    "Determine an appropriate snap name for this project. "
                    "Snap names must be lowercase, alphanumeric, and may "
                    "contain hyphens. Replace 'TODO-snap-name' in "
                    "snapcraft.yaml with the correct name."
                ),
            )
            sanitised = "TODO-snap-name"
        return sanitised

    def _derive_version(self) -> str:
        if self._report.build_systems:
            bs = self._report.build_systems[0]
            if bs.version:
                return bs.version
        return "git"

    def _add_confinement(self, doc: dict[str, Any]) -> None:
        # Always start with devmode; the user tightens to strict later.
        doc["confinement"] = "devmode"

    def _add_platforms(self, doc: dict[str, Any]) -> None:
        doc["platforms"] = {"amd64": None, "arm64": None, "armhf": None}

    # ------------------------------------------------------------------
    # Standard (non-Frame) patterns
    # ------------------------------------------------------------------

    def _add_standard_apps(self, doc: dict[str, Any]) -> None:
        apps: dict[str, Any] = {}
        snap_name = doc["name"]

        if self._report.daemons:
            for daemon in self._report.daemons:
                entry: dict[str, Any] = {}
                entry["command"] = daemon.command or "bin/TODO-command"
                if daemon.command is None:
                    self._note_gap(
                        f"daemon-command-{daemon.name}",
                        f"Could not determine command for daemon '{daemon.name}'.",
                        ai_prompt=(
                            f"Determine the executable command for the "
                            f"'{daemon.name}' daemon.  It was inferred from "
                            f"'{daemon.source_file}'.  Replace "
                            "'bin/TODO-command' in snapcraft.yaml with the "
                            "correct relative path inside the snap (e.g. "
                            "'bin/myapp')."
                        ),
                    )
                entry["daemon"] = daemon.daemon_type
                entry["restart-condition"] = daemon.restart_condition
                if daemon.plugs or self._report.plugs:
                    plug_names = list(daemon.plugs) + [
                        p.name for p in self._report.plugs
                        if p.name not in daemon.plugs
                    ]
                    entry["plugs"] = plug_names
                apps[daemon.name] = entry
        elif self._report.build_systems:
            bs = self._report.build_systems[0]
            entry = {}
            if bs.entry_points:
                entry["command"] = bs.entry_points[0]
            else:
                entry["command"] = "bin/TODO-command"
                self._note_gap(
                    "app-command",
                    f"Could not determine app command for {snap_name}.",
                    ai_prompt=(
                        "Determine the entry-point command for the main "
                        f"application in '{self._report.path}'. Replace "
                        "'bin/TODO-command' in snapcraft.yaml with the "
                        "correct relative path inside the snap."
                    ),
                )
            if self._report.plugs:
                entry["plugs"] = [p.name for p in self._report.plugs]
            apps[snap_name] = entry
        else:
            apps[snap_name] = {
                "command": "bin/TODO-command",
                "plugs": ["network"],
            }
            self._note_gap(
                "app-command",
                "No build system or daemon detected; could not determine app command.",
                ai_prompt=(
                    "No build system was detected in this repository. "
                    "Manually determine the application entry point and "
                    "replace 'bin/TODO-command' in snapcraft.yaml."
                ),
            )

        doc["apps"] = apps

    def _add_standard_parts(self, doc: dict[str, Any]) -> None:
        snap_name = doc["name"]
        parts: dict[str, Any] = {}

        if self._report.build_systems:
            bs = self._report.build_systems[0]
            part: dict[str, Any] = {
                "plugin": bs.plugin,
                "source": ".",
            }
            if bs.build_packages:
                part["build-packages"] = bs.build_packages
            if bs.stage_packages:
                part["stage-packages"] = bs.stage_packages

            # Plugin-specific hints.
            if bs.plugin == "go":
                part["build-snaps"] = ["go/1.22/stable"]
            elif bs.plugin == "npm" and bs.version:
                part["npm-node-version"] = bs.version
            elif bs.plugin in ("poetry", "uv"):
                pass  # No extra keys needed for these.

            parts[snap_name] = part
        else:
            parts["TODO-part"] = {
                "plugin": "nil",
                "source": ".",
                "override-build": "# TODO: add build commands",
            }
            self._note_gap(
                "parts",
                "No build system detected; generated a nil-plugin skeleton.",
                ai_prompt=(
                    "No build system was automatically detected. "
                    "Examine the repository's build tooling and replace the "
                    "'TODO-part' part in snapcraft.yaml with the appropriate "
                    "plugin and configuration."
                ),
            )

        doc["parts"] = parts

    # ------------------------------------------------------------------
    # Ubuntu Frame pattern
    # ------------------------------------------------------------------

    def _add_ubuntu_frame_plugs(self, doc: dict[str, Any]) -> None:
        """Add the top-level gpu-2404 content interface plug."""
        doc["plugs"] = {
            "gpu-2404": {
                "interface": "content",
                "target": "$SNAP/gpu-2404",
                "default-provider": "mesa-2404",
            }
        }

    def _add_ubuntu_frame_environment(self, doc: dict[str, Any]) -> None:
        """Add the top-level environment block for Ubuntu Frame."""
        doc["environment"] = {
            "XDG_CACHE_HOME": "$SNAP_USER_COMMON/.cache",
            "XDG_CONFIG_HOME": "$SNAP_USER_DATA/.config",
            "XDG_CONFIG_DIRS": "$SNAP/etc/xdg",
            "XDG_DATA_DIRS": "$SNAP/usr/local/share:$SNAP/usr/share",
            "XKB_CONFIG_ROOT": "$SNAP/usr/share/X11/xkb",
        }

    def _add_ubuntu_frame_layout(self, doc: dict[str, Any]) -> None:
        """Add the layout block required by the gpu-2404 interface."""
        layout: dict[str, Any] = {
            "/usr/share/libdrm": {"bind": "$SNAP/gpu-2404/libdrm"},
            "/usr/share/drirc.d": {"symlink": "$SNAP/gpu-2404/drirc.d"},
            "/usr/share/fonts": {"bind": "$SNAP/usr/share/fonts"},
            "/usr/share/icons": {"bind": "$SNAP/usr/share/icons"},
            "/usr/share/sounds": {"bind": "$SNAP/usr/share/sounds"},
            "/etc/fonts": {"bind": "$SNAP/etc/fonts"},
        }

        # Add toolkit-specific layout entries.
        for bs in self._report.build_systems:
            if bs.name.startswith("Qt") or bs.name.startswith("GTK"):
                layout["/usr/share/mime"] = {"bind": "$SNAP/usr/share/mime"}
                layout["/etc/gtk-3.0"] = {"bind": "$SNAP/etc/gtk-3.0"}

        doc["layout"] = layout

    def _add_ubuntu_frame_apps(self, doc: dict[str, Any]) -> None:
        """Add the dual interactive-app + daemon app entries for Frame."""
        snap_name = doc["name"]
        command = self._derive_frame_command()

        common_plugs = ["opengl", "wayland"]
        common_command_chain = ["bin/gpu-2404-wrapper", "bin/wayland-launch"]
        common_env: dict[str, str] = {}

        # Collect toolkit-specific env vars.
        for finding in self._report.raw_findings:
            if "env_vars" in finding.metadata:
                common_env.update(finding.metadata["env_vars"])

        app_entry: dict[str, Any] = {
            "command-chain": common_command_chain,
            "command": command,
            "plugs": common_plugs,
        }
        daemon_entry: dict[str, Any] = {
            "daemon": "simple",
            "restart-delay": "3s",
            "restart-condition": "always",
            "command-chain": common_command_chain,
            "command": command,
            "plugs": common_plugs,
        }

        if common_env:
            app_entry["environment"] = common_env
            daemon_entry["environment"] = common_env

        doc["apps"] = {
            snap_name: app_entry,
            "daemon": daemon_entry,
        }

    def _add_ubuntu_frame_parts(self, doc: dict[str, Any]) -> None:
        """Add parts for the Ubuntu Frame template (app + setup + gpu-2404)."""
        snap_name = doc["name"]
        parts: dict[str, Any] = {}

        # Application part.
        if self._report.build_systems:
            bs = self._report.build_systems[0]
            app_part: dict[str, Any] = {"plugin": bs.plugin, "source": "."}
            if bs.build_packages:
                app_part["build-packages"] = bs.build_packages
            # Merge toolkit-specific stage-packages.
            stage_pkgs = list(bs.stage_packages)
            for finding in self._report.raw_findings:
                for pkg in finding.metadata.get("stage_packages", []):
                    if pkg not in stage_pkgs:
                        stage_pkgs.append(pkg)
            if stage_pkgs:
                app_part["stage-packages"] = stage_pkgs
        else:
            app_part = {
                "plugin": "nil",
                "source": ".",
                "override-build": "# TODO: add build commands",
            }
            self._note_gap(
                "frame-app-part",
                "No build system detected for Ubuntu Frame app part.",
                ai_prompt=(
                    "The project appears to be a graphical application for "
                    "Ubuntu Frame but no build system was detected. Examine "
                    "the source and replace the nil-plugin part with the "
                    "appropriate plugin."
                ),
            )
        parts[snap_name] = app_part

        # Setup part (wayland-launch scripts).
        parts["setup"] = {
            "plugin": "dump",
            "source": "https://github.com/canonical/iot-example-graphical-snap.git",
            "source-subdir": "wayland-launch",
            "override-build": textwrap.dedent(
                """\
                PLUGS="opengl wayland gpu-2404"
                sed --in-place "s/%PLUGS%/$PLUGS/g" $CRAFT_PART_BUILD/bin/wayland-launch
                sed --in-place "s/%PLUGS%/$PLUGS/g" $CRAFT_PART_BUILD/bin/setup.sh
                craftctl default
                """
            ),
            "stage-packages": ["inotify-tools"],
        }

        # gpu-2404 part.
        parts["gpu-2404"] = {
            "after": [snap_name, "setup"],
            "source": "https://github.com/canonical/gpu-snap.git",
            "plugin": "dump",
            "override-prime": textwrap.dedent(
                """\
                craftctl default
                ${CRAFT_PART_SRC}/bin/gpu-2404-cleanup mesa-2404
                """
            ),
            "prime": ["bin/gpu-2404-wrapper"],
        }

        doc["parts"] = parts

    def _derive_frame_command(self) -> str:
        """Derive the app command for the Ubuntu Frame entry."""
        if self._report.build_systems:
            bs = self._report.build_systems[0]
            if bs.entry_points:
                return bs.entry_points[0]
        self._note_gap(
            "frame-command",
            "Could not determine the application command for Ubuntu Frame.",
            ai_prompt=(
                "Determine the executable that should be launched by Ubuntu "
                "Frame (the main Wayland client entry point). Replace "
                "'bin/TODO-command' in snapcraft.yaml with the correct path."
            ),
        )
        return "bin/TODO-command"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _note_gap(self, key: str, description: str, *, ai_prompt: str) -> None:
        """Record a gap and create a corresponding AIActionItem."""
        self._gaps.append(description)
        self._ai_actions.append(
            AIActionItem(
                category=f"scaffold-gap:{key}",
                severity=Severity.WARNING,
                description=description,
                suggested_fix="Review and fill in the TODO marker in snapcraft.yaml.",
                ai_prompt=ai_prompt,
                reference_url=(
                    "https://documentation.ubuntu.com/snapcraft/stable/"
                ),
            )
        )

    def _compute_confidence(self) -> float:
        """Compute an overall confidence score for the scaffold."""
        score = 1.0
        # Each gap reduces confidence.
        score -= min(len(self._gaps) * 0.1, 0.5)
        # No build system detected is a big penalty.
        if not self._report.build_systems:
            score -= 0.3
        return round(max(score, 0.1), 2)

    @staticmethod
    def _dump(doc: dict[str, Any]) -> str:
        """Serialise *doc* to a clean YAML string."""
        return yaml.dump(
            doc,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=2,
            width=88,
        )
