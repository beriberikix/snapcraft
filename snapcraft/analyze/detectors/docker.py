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

"""Dockerfile detector for ``snapcraft analyze``.

Parses a ``Dockerfile`` (or ``Dockerfile.*``) to extract:
- Base image (which may hint at the language/runtime)
- Installed packages (``apt-get install`` / ``apk add``)
- Exposed ports (→ ``network-bind`` plug)
- ``CMD`` / ``ENTRYPOINT`` (→ app command)
- ``USER root`` (→ confinement warning)
- Hardcoded absolute paths (→ layout / path-rewrite warnings)
"""

from __future__ import annotations

import re
from pathlib import Path

from snapcraft.analyze.detectors import BaseDetector, registry
from snapcraft.analyze.models import (
    DetectorFinding,
    FindingCategory,
    Severity,
)

# Mapping from well-known base images to the most likely snapcraft plugin.
_IMAGE_TO_PLUGIN: dict[str, str] = {
    "golang": "go",
    "python": "python",
    "node": "npm",
    "rust": "rust",
    "maven": "maven",
    "gradle": "gradle",
    "openjdk": "gradle",
    "eclipse-temurin": "gradle",
    "dotnet": "dotnet",
    "mcr.microsoft.com/dotnet": "dotnet",
}

# Paths that are legitimate at build time but become confinement problems
# once running inside a strict snap.
_SUSPICIOUS_PATHS = re.compile(
    r"/etc/(?!hosts|resolv\.conf|timezone|localtime)"
    r"|/usr/(?:bin|sbin|local/bin|local/sbin)"
    r"|/var/(?:lib|run|log)"
    r"|/opt/"
    r"|/srv/"
    r"|/root/"
    r"|/home/(?!\$)"
)


@registry.register
class DockerDetector(BaseDetector):
    """Detect and analyse a ``Dockerfile`` in the repository root."""

    name = "docker"

    def detect(self) -> list[DetectorFinding]:
        dockerfile = self._file_exists("Dockerfile", "dockerfile")
        if dockerfile is None:
            # Also check for Dockerfile.<variant>
            candidates = list(self._path.glob("Dockerfile.*"))
            if not candidates:
                return []
            dockerfile = candidates[0]

        return self._analyse(dockerfile)

    def _analyse(self, path: Path) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        text = self._read_text(path)
        lines = text.splitlines()

        findings.extend(self._detect_base_image(lines, path))
        findings.extend(self._detect_exposed_ports(lines, path))
        findings.extend(self._detect_command(lines, path))
        findings.extend(self._detect_user_root(lines, path))
        if self._deep:
            findings.extend(self._detect_hardcoded_paths(lines, path))

        return findings

    # ------------------------------------------------------------------

    def _detect_base_image(
        self, lines: list[str], path: Path
    ) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue
            image = stripped[5:].split()[0].lower()
            # Ignore multi-stage alias lines like "FROM builder AS final"
            for key, plugin in _IMAGE_TO_PLUGIN.items():
                if key in image:
                    findings.append(
                        DetectorFinding(
                            category=FindingCategory.BUILD_SYSTEM,
                            severity=Severity.INFO,
                            description=(
                                f"Dockerfile FROM image '{image}' suggests "
                                f"plugin: {plugin}"
                            ),
                            file=str(path.relative_to(self._path)),
                            line=lineno,
                            metadata={"plugin_hint": plugin, "from_image": image},
                        )
                    )
                    break
        return findings

    def _detect_exposed_ports(
        self, lines: list[str], path: Path
    ) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        for lineno, line in enumerate(lines, start=1):
            if re.match(r"^\s*EXPOSE\b", line, re.IGNORECASE):
                findings.append(
                    DetectorFinding(
                        category=FindingCategory.NETWORK,
                        severity=Severity.INFO,
                        description=(
                            "Dockerfile EXPOSE found; snap will need "
                            "the 'network-bind' interface plug."
                        ),
                        file=str(path.relative_to(self._path)),
                        line=lineno,
                        metadata={"plug_hint": "network-bind"},
                    )
                )
                break  # Only need to report once.
        return findings

    def _detect_command(
        self, lines: list[str], path: Path
    ) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            m = re.match(r"^(CMD|ENTRYPOINT)\s+(.*)", stripped, re.IGNORECASE)
            if m:
                directive = m.group(1).upper()
                raw_cmd = m.group(2).strip()
                # Normalise JSON-array form.
                cmd = re.sub(r'[\[\]",]', " ", raw_cmd).split()
                command = " ".join(cmd).strip() if cmd else raw_cmd

                # Strip path prefixes that won't exist inside the snap.
                for prefix in ("/usr/bin/", "/usr/local/bin/", "/bin/", "/sbin/"):
                    if command.startswith(prefix):
                        command = command[len(prefix):]

                findings.append(
                    DetectorFinding(
                        category=FindingCategory.DAEMON,
                        severity=Severity.INFO,
                        description=(
                            f"Dockerfile {directive} suggests app command: "
                            f"bin/{command.split()[0]}"
                        ),
                        file=str(path.relative_to(self._path)),
                        line=lineno,
                        metadata={"command_hint": command},
                    )
                )
        return findings

    def _detect_user_root(
        self, lines: list[str], path: Path
    ) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []
        for lineno, line in enumerate(lines, start=1):
            if re.match(r"^\s*USER\s+(?:0|root)\b", line, re.IGNORECASE):
                findings.append(
                    DetectorFinding(
                        category=FindingCategory.CONFINEMENT,
                        severity=Severity.ERROR,
                        description=(
                            "Dockerfile sets USER root. Running as root inside "
                            "a strict snap is not permitted and will be denied "
                            "by AppArmor."
                        ),
                        file=str(path.relative_to(self._path)),
                        line=lineno,
                        metadata={"violation_type": "user-root"},
                    )
                )
        return findings

    def _detect_hardcoded_paths(
        self, lines: list[str], path: Path
    ) -> list[DetectorFinding]:
        """Scan COPY / ADD / RUN instructions for suspicious absolute paths."""
        findings: list[DetectorFinding] = []
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not re.match(r"^(COPY|ADD|RUN|ENV|VOLUME)\b", stripped, re.IGNORECASE):
                continue
            for m in _SUSPICIOUS_PATHS.finditer(stripped):
                hit = m.group(0)
                findings.append(
                    DetectorFinding(
                        category=FindingCategory.HARDCODED_PATH,
                        severity=Severity.WARNING,
                        description=(
                            f"Hardcoded path '{hit}…' in Dockerfile. "
                            "This path will not exist at the expected location "
                            "inside a strict snap; use $SNAP, $SNAP_DATA, "
                            "or $SNAP_COMMON instead, or add a 'layout:' entry."
                        ),
                        file=str(path.relative_to(self._path)),
                        line=lineno,
                        metadata={"hardcoded_path": hit, "violation_type": "hardcoded-path"},
                    )
                )
        return findings
