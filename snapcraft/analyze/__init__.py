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

"""Snapcraft analyze engine.

This package implements the ``snapcraft analyze`` command, which inspects a
local repository and produces:

* A build-system / language identification
* Daemon / service configuration hints
* Snap interface (plug) recommendations
* Strict-confinement warnings
* A best-effort ``snapcraft.yaml`` scaffold
* Structured AI action items (machine-readable for downstream AI agents)
"""

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

__all__ = [
    "AIActionItem",
    "AnalysisReport",
    "BuildSystemInfo",
    "ConfinementWarning",
    "DaemonInfo",
    "DetectorFinding",
    "FindingCategory",
    "PlugInfo",
    "ScaffoldResult",
    "Severity",
]
