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
from typing import TYPE_CHECKING

from snapcraft.analyze.models import (
    AIActionItem,
    ConfinementWarning,
    DetectorFinding,
    FindingCategory,
    Severity,
)

if TYPE_CHECKING:
    from pathlib import Path

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
    # Pass 2: always-on shallow Python source scan (depth 0 + 1).        #
    # Skipped when --deep is active to avoid duplicate warnings for the   #
    # same Python files (the deep scan covers all depths including .py).  #
    # ------------------------------------------------------------------ #
    if not deep:
        shallow_warnings, shallow_actions = _scan_python_shallow(path)
        warnings.extend(shallow_warnings)
        ai_actions.extend(shallow_actions)

    # ------------------------------------------------------------------ #
    # Pass 3: deep source-file scan (opt-in).                             #
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

    elif violation_type == "notify-unverified":
        fix = (
            "Either add a readiness-notification call to the service's startup "
            "code (Python: `import sdnotify; sdnotify.SystemdNotifier().notify"
            "('READY=1')`, Go: `daemon.SdNotify(false, daemon.SdNotifyReady)`, "
            'C: `sd_notify(0, "READY=1");`) '
            "or change `daemon: notify` to `daemon: simple` in snapcraft.yaml."
        )
        prompt = (
            f"The systemd unit '{finding.file}' declares Type=notify but no "
            "sd_notify / sdnotify / READY=1 call was found in the source. "
            "A daemon: notify service that never calls sd_notify will be "
            "killed by snapd on every start. Either:\n"
            "1. Add readiness notification. Language examples:\n"
            "   Python:  import sdnotify; sdnotify.SystemdNotifier().notify('READY=1')\n"
            "   Go:      daemon.SdNotify(false, daemon.SdNotifyReady)  "
            "(pkg: github.com/coreos/go-systemd/v22/daemon)\n"
            '   C/C++:   sd_notify(0, "READY=1");  (link with -lsystemd)\n'
            "   Rust:    libsystemd::daemon::notify(false, &[NotifyState::Ready]);\n"
            "2. Or use `daemon: simple` in snapcraft.yaml "
            "(simpler, no readiness notification required)."
        )
        ref = "https://snapcraft.io/docs/services-and-daemons"

    elif violation_type == "restart-always":
        fix = (
            "Change `restart-condition: always` to `restart-condition: "
            "on-failure` unless the daemon is designed to never exit with "
            "code 0. Using 'always' on a service that can exit cleanly will "
            "trigger a restart loop and eventually hit the start-limit."
        )
        prompt = (
            f"The systemd unit '{finding.file}' sets Restart=always. "
            "This causes the service to restart even on a clean exit (code 0). "
            "If the daemon can ever exit intentionally, this will produce "
            "a restart loop that hits systemd's start-limit and may cause "
            "alerts. Change `restart-condition: always` to "
            "`restart-condition: on-failure` in snapcraft.yaml."
        )
        ref = "https://snapcraft.io/docs/services-and-daemons"

    elif violation_type == "missing-init-py":
        directory = finding.metadata.get("directory", "package")
        fix = (
            f"Create an empty `{directory}/__init__.py` file to make the "
            "directory an explicit Python package."
        )
        prompt = (
            f"The Python package directory '{directory}/' has no __init__.py. "
            "Without it, the package may not be importable at snap runtime, "
            "especially if the snap's Python environment uses a different "
            "sys.path order than the development environment. "
            f"Create an empty file: `touch {directory}/__init__.py`"
        )
        ref = "https://docs.python.org/3/reference/import.html#package-relative-imports"

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


def _scan_python_shallow(
    path: Path,
) -> tuple[list[ConfinementWarning], list[AIActionItem]]:
    """Always-on scan of Python source files at project root and one level deep.

    Checks for hardcoded absolute paths that will be denied under strict
    confinement.  This scan runs without ``--deep`` so that the most common
    case (a ``main.py`` or top-level package) is always covered.

    :param path: Repository root.
    :returns: A ``(warnings, ai_actions)`` pair.
    """
    warnings: list[ConfinementWarning] = []
    ai_actions: list[AIActionItem] = []

    # Collect .py files at depth 0 (root) and depth 1 (one subdirectory).
    candidates: list[Path] = list(path.glob("*.py"))
    try:
        for subdir in path.iterdir():
            if subdir.is_dir() and subdir.name not in _SKIP_DIRS:
                candidates.extend(subdir.glob("*.py"))
    except OSError:
        pass

    for src in candidates:
        rel = str(src.relative_to(path))
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _HARDCODED_PATH_RE.finditer(line):
                hit = m.group(1)
                warning = ConfinementWarning(
                    violation_type="hardcoded-path",
                    description=(
                        f"Hardcoded path '{hit}…' found in Python source."
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

    return warnings, ai_actions


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
                m = re.search(pattern, text)
                if m:
                    matched_path = m.group(0)
                    # Find the line number of the match.
                    lineno = text[: m.start()].count("\n") + 1
                    warning = ConfinementWarning(
                        violation_type="privileged-socket",
                        description=(
                            f"Privileged socket path '{matched_path}' referenced "
                            f"in '{rel}'."
                        ),
                        file=rel,
                        line=lineno,
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
                            line=lineno,
                            suggested_fix=warning.suggested_fix,
                            ai_prompt=(
                                f"'{rel}' line {lineno} accesses the privileged "
                                f"socket '{matched_path}'. This requires "
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
