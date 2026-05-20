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

"""Typed data models for the snapcraft analyze engine.

These models are the internal currency of the analysis pipeline and are
designed to be serialised to JSON so the output can be consumed by both
human-facing formatters and downstream AI migration agents.
"""

from __future__ import annotations

import enum
from typing import Any

import pydantic


class Severity(str, enum.Enum):
    """Severity level for a finding or action item."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


class FindingCategory(str, enum.Enum):
    """Category tag for a detector finding."""

    BUILD_SYSTEM = "build-system"
    DAEMON = "daemon"
    CONFINEMENT = "confinement"
    HARDCODED_PATH = "hardcoded-path"
    HARDWARE = "hardware"
    NETWORK = "network"
    GUI = "gui"
    UBUNTU_FRAME = "ubuntu-frame"
    GENERIC = "generic"

    def __str__(self) -> str:
        return self.value


class DetectorFinding(pydantic.BaseModel):
    """A single raw finding emitted by a detector.

    Findings are low-level observations.  The AnalyzeService aggregates them
    into the higher-level structures (BuildSystemInfo, DaemonInfo, etc.) that
    populate the final AnalysisReport.
    """

    category: FindingCategory
    severity: Severity
    description: str
    file: str | None = None
    line: int | None = None
    # Free-form structured payload; each detector documents its own keys.
    metadata: dict[str, Any] = pydantic.Field(default_factory=dict)

    model_config = pydantic.ConfigDict(extra="forbid")


class AIActionItem(pydantic.BaseModel):
    """A structured instruction that an AI migration agent can act on.

    Every blocker or gap found during analysis is expressed as an AIActionItem
    so that a downstream agent has all the context it needs without re-reading
    the repository.
    """

    category: str
    severity: Severity
    description: str
    file: str | None = None
    line: int | None = None
    suggested_fix: str
    ai_prompt: str
    reference_url: str | None = None

    model_config = pydantic.ConfigDict(extra="forbid")


class BuildSystemInfo(pydantic.BaseModel):
    """Information about a detected build system / language ecosystem."""

    name: str
    """Human-readable name (e.g. ``Go``, ``Python/pip``)."""

    plugin: str
    """Snapcraft plugin to use (e.g. ``go``, ``python``, ``cmake``)."""

    version: str | None = None
    """Detected language/toolchain version, if extractable."""

    build_packages: list[str] = pydantic.Field(default_factory=list)
    stage_packages: list[str] = pydantic.Field(default_factory=list)
    entry_points: list[str] = pydantic.Field(default_factory=list)
    """Binary names that should appear in ``apps:`` command fields."""

    confidence: float = 1.0
    """Detection confidence score between 0.0 and 1.0."""

    model_config = pydantic.ConfigDict(extra="forbid")


class DaemonInfo(pydantic.BaseModel):
    """Information about a detected background service."""

    name: str
    """Snap app name to use for this daemon."""

    daemon_type: str
    """Snapcraft daemon type: ``simple``, ``forking``, ``oneshot``, ``notify``."""

    command: str | None = None
    restart_condition: str = "on-failure"
    plugs: list[str] = pydantic.Field(default_factory=list)
    source_file: str | None = None
    """Path to the systemd unit or Dockerfile that was the source of this info."""

    model_config = pydantic.ConfigDict(extra="forbid")


class ConfinementWarning(pydantic.BaseModel):
    """A strict-confinement violation or concern found in the repository."""

    violation_type: str
    """Short machine-readable tag, e.g. ``hardcoded-path``, ``user-root``."""

    description: str
    file: str | None = None
    line: int | None = None
    suggested_fix: str

    model_config = pydantic.ConfigDict(extra="forbid")


class PlugInfo(pydantic.BaseModel):
    """A snap interface plug inferred from project analysis."""

    name: str
    reason: str
    auto_connect: bool = True

    model_config = pydantic.ConfigDict(extra="forbid")


class ScaffoldResult(pydantic.BaseModel):
    """The generated snapcraft.yaml scaffold."""

    yaml_content: str
    confidence: float
    """Overall confidence that the scaffold is correct (0.0–1.0)."""

    gaps: list[str] = pydantic.Field(default_factory=list)
    """Things the generator could not determine automatically."""

    model_config = pydantic.ConfigDict(extra="forbid")


class AnalysisReport(pydantic.BaseModel):
    """The complete, aggregated analysis report for a repository.

    This is the top-level model that is serialised to JSON when
    ``--format json`` is requested, or rendered as human-readable text by
    the default formatter.
    """

    path: str
    build_systems: list[BuildSystemInfo] = pydantic.Field(default_factory=list)
    daemons: list[DaemonInfo] = pydantic.Field(default_factory=list)
    plugs: list[PlugInfo] = pydantic.Field(default_factory=list)
    confinement_warnings: list[ConfinementWarning] = pydantic.Field(
        default_factory=list
    )
    scaffold: ScaffoldResult | None = None
    ai_actions: list[AIActionItem] = pydantic.Field(default_factory=list)
    raw_findings: list[DetectorFinding] = pydantic.Field(default_factory=list)
    is_ubuntu_frame_app: bool = False
    is_headless_daemon: bool = False

    model_config = pydantic.ConfigDict(extra="forbid")
