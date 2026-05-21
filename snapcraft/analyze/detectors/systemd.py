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

"""Systemd unit file detector for ``snapcraft analyze``.

Finds ``*.service`` files anywhere under the repository and maps their
``[Service]`` section to snapcraft daemon configuration.

Mapping:
  ``Type=simple``  → ``daemon: simple``
  ``Type=forking`` → ``daemon: forking``
  ``Type=oneshot`` → ``daemon: oneshot``
  ``Type=notify``  → ``daemon: notify``

The ``Restart=`` value is mapped to ``restart-condition:``::

  ``always``      → ``always``
  ``on-failure``  → ``on-failure``
  ``on-abnormal`` → ``on-abnormal``
  ``never``       → ``never``
  (anything else) → ``on-failure``   # safe default
"""

from __future__ import annotations

import configparser
import re
from pathlib import Path

from snapcraft.analyze.detectors import BaseDetector, registry
from snapcraft.analyze.models import (
    DaemonInfo,
    DetectorFinding,
    FindingCategory,
    Severity,
)

_DAEMON_TYPE_MAP: dict[str, str] = {
    "simple": "simple",
    "forking": "forking",
    "oneshot": "oneshot",
    "notify": "notify",
    "exec": "simple",  # systemd 'exec' is closest to snap 'simple'
    "idle": "simple",
}

# Patterns that indicate a service actively calls sd_notify to signal
# readiness. We search all source files for these; if none is found for a
# Type=notify unit, the daemon type is downgraded to 'simple' and a
# CONFINEMENT warning is emitted so the user knows why.
_NOTIFY_SIGNAL_RE = re.compile(
    r"sd_notify|sdnotify|systemd\.daemon|READY=1|notify_socket",
    re.IGNORECASE,
)

# Directories to skip when scanning source files for sd_notify signals.
_SOURCE_SKIP_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
     ".tox", ".venv", "venv", "env", "dist", "build", "target",
     ".mypy_cache", ".pytest_cache"}
)

# Source file extensions to scan for readiness notification patterns.
_NOTIFY_SOURCE_EXTENSIONS = (
    "*.py", "*.go", "*.rs", "*.c", "*.cpp", "*.h", "*.js", "*.ts", "*.sh",
)

_RESTART_MAP: dict[str, str] = {
    "always": "always",
    "on-failure": "on-failure",
    "on-abnormal": "on-abnormal",
    "on-abort": "on-failure",
    "on-watchdog": "on-failure",
    "never": "never",
    "no": "never",
}


@registry.register
class SystemdDetector(BaseDetector):
    """Detect systemd service units and map them to snap daemon config."""

    name = "systemd"

    def detect(self) -> list[DetectorFinding]:
        service_files = self._find_files("*.service")
        # Exclude any files under .git
        service_files = [
            f for f in service_files if ".git" not in f.parts
        ]
        if not service_files:
            return []

        # Compute the source notification scan once so that repositories with
        # multiple Type=notify units don't trigger O(N_services × repo_size)
        # full-tree scans.
        notify_in_source = self._check_notify_in_source()

        findings: list[DetectorFinding] = []
        for service_file in service_files:
            findings.extend(self._analyse_service(service_file, notify_in_source))
        return findings

    def _check_notify_in_source(self) -> bool:
        """Return True if any source file contains a readiness-notification call.

        Scans common source file types for ``sd_notify``, ``sdnotify``,
        ``systemd.daemon``, ``READY=1``, or ``notify_socket``.  Returns
        ``False`` if none is found (caller should downgrade ``daemon: notify``
        to ``daemon: simple``).
        """
        for ext in _NOTIFY_SOURCE_EXTENSIONS:
            for src_file in self._path.rglob(ext):
                if any(part in _SOURCE_SKIP_DIRS for part in src_file.parts):
                    continue
                if _NOTIFY_SIGNAL_RE.search(self._read_text(src_file)):
                    return True
        return False

    def _analyse_service(self, path: Path, notify_in_source: bool) -> list[DetectorFinding]:
        text = self._read_text(path)
        # configparser needs a dummy section header for bare INI files,
        # but .service files have real [Unit], [Service], [Install] sections.
        cfg = configparser.ConfigParser(strict=False)
        try:
            cfg.read_string(text)
        except configparser.Error:
            return []

        service_section = self._get_section(cfg, "Service")
        if service_section is None:
            return []

        daemon_type = self._map_daemon_type(service_section.get("type", "simple"))
        raw_exec = service_section.get("execstart", "")
        restart = self._map_restart(service_section.get("restart", "on-failure"))
        user = service_section.get("user", "")
        app_name = self._derive_app_name(path, raw_exec)
        command = self._clean_command(raw_exec)
        plugs = self._infer_plugs(raw_exec)

        rel_path = str(path.relative_to(self._path))
        findings: list[DetectorFinding] = []

        # Validate daemon: notify — if no readiness-notification call is found
        # in the source, downgrade to daemon: simple and emit a warning so the
        # user knows why.  A Type=notify daemon that never calls sd_notify will
        # be killed by systemd on every start.
        notify_unverified = False
        if daemon_type == "notify" and not notify_in_source:
            daemon_type = "simple"
            notify_unverified = True

        daemon_info = DaemonInfo(
            name=app_name,
            daemon_type=daemon_type,
            command=command,
            restart_condition=restart,
            plugs=plugs,
            source_file=rel_path,
        )
        findings.append(
            DetectorFinding(
                category=FindingCategory.DAEMON,
                severity=Severity.INFO,
                description=(
                    f"Systemd unit '{path.name}' → daemon: {daemon_type}"
                ),
                file=rel_path,
                metadata=daemon_info.model_dump(),
            )
        )

        if notify_unverified:
            findings.append(
                DetectorFinding(
                    category=FindingCategory.CONFINEMENT,
                    severity=Severity.WARNING,
                    description=(
                        f"Systemd unit '{path.name}' declares Type=notify but "
                        "no sd_notify / sdnotify / READY=1 call was found in "
                        "the source. Defaulted to daemon: simple. Add a "
                        "readiness-notification call or change Type=simple in "
                        "the service file."
                    ),
                    file=rel_path,
                    metadata={"violation_type": "notify-unverified"},
                )
            )

        if restart == "always":
            findings.append(
                DetectorFinding(
                    category=FindingCategory.CONFINEMENT,
                    severity=Severity.WARNING,
                    description=(
                        f"Systemd unit '{path.name}' sets Restart=always. "
                        "This restarts the service even on a clean exit "
                        "(code 0). If the daemon can exit intentionally, "
                        "this will trigger a restart loop and hit the "
                        "start-limit. Consider restart-condition: on-failure."
                    ),
                    file=rel_path,
                    metadata={"violation_type": "restart-always"},
                )
            )

        if user.lower() in ("root", "0"):
            findings.append(
                DetectorFinding(
                    category=FindingCategory.CONFINEMENT,
                    severity=Severity.ERROR,
                    description=(
                        f"Systemd unit '{path.name}' sets User=root. "
                        "Snaps run as the installing user; running as root "
                        "requires the 'system-usernames' interface and "
                        "explicit Snap Store approval."
                    ),
                    file=rel_path,
                    metadata={"violation_type": "user-root"},
                )
            )

        return findings

    @staticmethod
    def _get_section(
        cfg: configparser.ConfigParser, section: str
    ) -> configparser.SectionProxy | None:
        for name in cfg.sections():
            if name.lower() == section.lower():
                return cfg[name]
        return None

    @staticmethod
    def _map_daemon_type(raw: str) -> str:
        return _DAEMON_TYPE_MAP.get(raw.strip().lower(), "simple")

    @staticmethod
    def _map_restart(raw: str) -> str:
        return _RESTART_MAP.get(raw.strip().lower(), "on-failure")

    @staticmethod
    def _derive_app_name(path: Path, exec_start: str) -> str:
        """Best-effort app name: stem of service file, then binary name."""
        stem = path.stem
        # Drop common suffixes like myapp.service → myapp
        if stem.endswith(".service"):
            stem = stem[: -len(".service")]
        return stem.replace(".", "-")

    @staticmethod
    def _clean_command(raw: str) -> str | None:
        """Strip absolute path prefixes that won't survive inside the snap."""
        if not raw:
            return None
        # Take only the first word (the executable).
        cmd = raw.strip().split()[0]
        for prefix in ("/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/bin/", "/sbin/"):
            if cmd.startswith(prefix):
                return f"bin/{cmd[len(prefix):]}"
        if cmd.startswith("$"):
            return None  # env-var substituted, can't resolve statically
        return f"bin/{Path(cmd).name}"

    @staticmethod
    def _infer_plugs(exec_start: str) -> list[str]:
        """Infer likely plugs from the ExecStart command."""
        plugs: list[str] = []
        if not exec_start:
            return plugs
        lower = exec_start.lower()
        if any(w in lower for w in ("network", "listen", "bind", "connect")):
            plugs.append("network")
        if re.search(r"/dev/tty|/dev/serial|/dev/usb", lower):
            plugs.append("serial-port")
        if re.search(r"/dev/i2c", lower):
            plugs.append("i2c")
        if re.search(r"/dev/spi", lower):
            plugs.append("spi")
        if re.search(r"/dev/gpio|gpiod", lower):
            plugs.append("gpio")
        return plugs
