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

"""Confinement warning scanner for ``snapcraft analyze``.

Converts raw :class:`~snapcraft.analyze.models.DetectorFinding` objects
(from detectors) and source-file scans (when ``--deep`` is used) into
structured :class:`~snapcraft.analyze.models.ConfinementWarning` and
:class:`~snapcraft.analyze.models.AIActionItem` objects.

Shallow mode (always active):
  * USER root in Dockerfiles / systemd units  (from detector findings)
  * Hardcoded paths in Dockerfiles            (from detector findings)
  * Privileged sockets                        (from detector findings)

Deep mode (``--deep`` flag):
  * Hardcoded absolute paths in source code
  * Direct writes to /etc, /var, /usr
  * /var/run/docker.sock usage
"""

from __future__ import annotations

import re
from pathlib import Path

from snapcraft.analyze.models import (
    AIActionItem,
    ConfinementWarning,
    DetectorFinding,
    FindingCategory,
    Severity,
)

# Paths that are clearly problematic inside a strict snap.
_HARDCODED_PATH_RE = re.compile(
    r"""
    (?<![\w/])               # not in the middle of a longer path segment or word
    (
      /etc/(?!hosts\b|resolv\.conf\b|timezone\b|localtime\b|passwd\b|group\b|os-release\b)
    | /var/(?:lib|run|log|cache|spool)/
    | /usr/(?:bin|sbin|local/bin|local/sbin|lib|share)/
    | /opt/
    | /srv/
    | /root/
    | /tmp/
    )
    """,
    re.VERBOSE,
)

# Source file extensions to scan in deep mode.
_DEEP_EXTENSIONS = [
    "*.py", "*.go", "*.rs",
    "*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp",
    "*.js", "*.ts", "*.sh",
    "*.yaml", "*.yml", "*.json", "*.toml", "*.cfg", "*.ini", "*.conf",
]

_SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
     ".tox", ".venv", "venv", "env", "dist", "build", "target"}
)

# Privileged sockets that a snap should never directly access.
# Note: /var/run is a symlink to /run on modern systems, so both paths exist.
# The pattern for bare /run/docker.sock uses a negative lookbehind to avoid
# double-matching when /var/run/docker.sock is already present in the same text.
_PRIVILEGED_SOCKETS = [
    r"/var/run/docker\.sock",
    r"(?<!/var)/run/docker\.sock",
    r"/run/containerd\.sock",
    r"/var/run/libvirt",
]


def build_confinement_warnings(
    findings: list[DetectorFinding],
    path: Path,
    *,
    deep: bool = False,
) -> tuple[list[ConfinementWarning], list[AIActionItem]]:
    """Produce confinement warnings and AI action items from *findings*.

    :param findings: Raw findings from the detector pipeline.
    :param path: Repository root (used for deep source scanning).
    :param deep: When ``True``, scan source files for hardcoded paths.
    :returns: A ``(warnings, ai_actions)`` pair.
    """
    warnings: list[ConfinementWarning] = []
    ai_actions: list[AIActionItem] = []

    # ------------------------------------------------------------------ #
    # Pass 1: promote relevant detector findings to typed warnings.       #
    # ------------------------------------------------------------------ #
    for finding in findings:
        if finding.category == FindingCategory.CONFINEMENT:
            vtype = finding.metadata.get("violation_type", "unknown")
            warning, action = _finding_to_warning_and_action(finding, vtype)
            warnings.append(warning)
            ai_actions.append(action)

        elif finding.category == FindingCategory.HARDCODED_PATH:
            hp = finding.metadata.get("hardcoded_path", "unknown path")
            warning = ConfinementWarning(
                violation_type="hardcoded-path",
                description=finding.description,
                file=finding.file,
                line=finding.line,
                suggested_fix=(
                    f"Replace '{hp}…' with a $SNAP_DATA or $SNAP_COMMON "
                    "path, or add a 'layout:' entry mapping it."
                ),
            )
            action = AIActionItem(
                category="hardcoded-path",
                severity=Severity.WARNING,
                description=finding.description,
                file=finding.file,
                line=finding.line,
                suggested_fix=warning.suggested_fix,
                ai_prompt=(
                    f"The file '{finding.file}' references the hardcoded "
                    f"path '{hp}'. In a strictly confined snap this path is "
                    "not writable. Either:\n"
                    "1. Add a `layout:` entry: "
                    f"  `{hp}: {{bind: $SNAP_DATA{hp}}}`\n"
                    "2. Or patch the source to use the `$SNAP_DATA` or "
                    "`$SNAP_COMMON` environment variable instead.\n"
                    "Apply the fix that requires the fewest source changes."
                ),
                reference_url="https://snapcraft.io/docs/snap-layouts",
            )
            warnings.append(warning)
            ai_actions.append(action)

    # ------------------------------------------------------------------ #
    # Pass 2: deep source-file scan (opt-in).                             #
    # ------------------------------------------------------------------ #
    if deep:
        deep_warnings, deep_actions = _scan_source_files(path)
        warnings.extend(deep_warnings)
        ai_actions.extend(deep_actions)

    return warnings, ai_actions


def _finding_to_warning_and_action(
    finding: DetectorFinding, violation_type: str
) -> tuple[ConfinementWarning, AIActionItem]:
    if violation_type == "user-root":
        fix = (
            "Remove the USER root / User=root directive. "
            "Snaps run as the installing user. If root privileges are "
            "genuinely required, request the 'system-usernames' Snap Store "
            "assertion."
        )
        prompt = (
            f"The file '{finding.file}' (line {finding.line}) sets the "
            "process to run as root. This is not allowed in a strictly "
            "confined snap without a Store-granted 'system-usernames' "
            "assertion. Remove the USER/User=root directive and rework any "
            "privileged operations to use the appropriate snap interface "
            "(e.g. 'hardware-observe', 'system-files')."
        )
        ref = "https://snapcraft.io/docs/system-usernames"
    else:
        fix = "Review and remediate the confinement violation."
        prompt = (
            f"Confinement issue '{violation_type}' found in '{finding.file}' "
            f"(line {finding.line}): {finding.description}"
        )
        ref = "https://snapcraft.io/docs/security-sandboxing"

    warning = ConfinementWarning(
        violation_type=violation_type,
        description=finding.description,
        file=finding.file,
        line=finding.line,
        suggested_fix=fix,
    )
    action = AIActionItem(
        category=violation_type,
        severity=finding.severity,
        description=finding.description,
        file=finding.file,
        line=finding.line,
        suggested_fix=fix,
        ai_prompt=prompt,
        reference_url=ref,
    )
    return warning, action


def _scan_source_files(
    path: Path,
) -> tuple[list[ConfinementWarning], list[AIActionItem]]:
    """Scan all source files under *path* for hardcoded paths and sockets."""
    warnings: list[ConfinementWarning] = []
    ai_actions: list[AIActionItem] = []

    for ext in _DEEP_EXTENSIONS:
        for src in path.rglob(ext):
            if any(part in _SKIP_DIRS for part in src.parts):
                continue
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(src.relative_to(path))

            # Hardcoded paths.
            for lineno, line in enumerate(text.splitlines(), start=1):
                for m in _HARDCODED_PATH_RE.finditer(line):
                    hit = m.group(1)
                    warning = ConfinementWarning(
                        violation_type="hardcoded-path",
                        description=(
                            f"Hardcoded path '{hit}…' found in source file."
                        ),
                        file=rel,
                        line=lineno,
                        suggested_fix=(
                            f"Replace '{hit}…' with a snap path variable "
                            "($SNAP, $SNAP_DATA, $SNAP_COMMON) or add a "
                            "'layout:' entry."
                        ),
                    )
                    action = AIActionItem(
                        category="hardcoded-path",
                        severity=Severity.WARNING,
                        description=warning.description,
                        file=rel,
                        line=lineno,
                        suggested_fix=warning.suggested_fix,
                        ai_prompt=(
                            f"In '{rel}' line {lineno}, the code references "
                            f"'{hit}'. Inside a strict snap this path is "
                            "read-only (in $SNAP) or does not exist. "
                            "Patch the code to read the path from an "
                            "environment variable (SNAP_DATA, SNAP_COMMON) "
                            "or add a snapcraft.yaml layout entry."
                        ),
                        reference_url="https://snapcraft.io/docs/snap-layouts",
                    )
                    warnings.append(warning)
                    ai_actions.append(action)

            # Privileged sockets.
            for pattern in _PRIVILEGED_SOCKETS:
                if re.search(pattern, text):
                    warning = ConfinementWarning(
                        violation_type="privileged-socket",
                        description=(
                            f"Privileged socket path '{pattern}' referenced "
                            f"in '{rel}'."
                        ),
                        file=rel,
                        suggested_fix=(
                            "Accessing privileged sockets (e.g. Docker, "
                            "containerd) from a snap requires the "
                            "'system-files' or a dedicated interface, "
                            "and Snap Store approval."
                        ),
                    )
                    ai_actions.append(
                        AIActionItem(
                            category="privileged-socket",
                            severity=Severity.ERROR,
                            description=warning.description,
                            file=rel,
                            suggested_fix=warning.suggested_fix,
                            ai_prompt=(
                                f"'{rel}' accesses a privileged socket "
                                f"matching '{pattern}'. This requires "
                                "explicit Snap Store approval via the "
                                "'system-files' interface. Consider whether "
                                "direct socket access is necessary, or if "
                                "the operation can be performed via a "
                                "higher-level snap interface."
                            ),
                            reference_url=(
                                "https://snapcraft.io/docs/system-files-interface"
                            ),
                        )
                    )
                    warnings.append(warning)

    return warnings, ai_actions
