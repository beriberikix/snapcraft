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

"""Detector plugin framework for ``snapcraft analyze``.

Adding a new detector
---------------------
1. Create a module under ``snapcraft/analyze/detectors/``.
2. Subclass :class:`BaseDetector` and set a unique :attr:`~BaseDetector.name`.
3. Implement :meth:`~BaseDetector.detect`.
4. Import and register the class with :data:`registry` in this module.

Example::

    from snapcraft.analyze.detectors import BaseDetector, registry
    from snapcraft.analyze.models import DetectorFinding, FindingCategory, Severity

    @registry.register
    class MyDetector(BaseDetector):
        name = "my-detector"

        def detect(self) -> list[DetectorFinding]:
            if not (self._path / "my-sentinel-file").exists():
                return []
            return [
                DetectorFinding(
                    category=FindingCategory.BUILD_SYSTEM,
                    severity=Severity.INFO,
                    description="Found my-sentinel-file",
                )
            ]
"""

from __future__ import annotations

import abc
import re
from pathlib import Path

from snapcraft.analyze.models import DetectorFinding


class BaseDetector(abc.ABC):
    """Abstract base class for all project detectors.

    :param path: Absolute path to the repository root to analyse.
    :param deep: When ``True``, perform exhaustive source-file scanning.
                 When ``False`` (the default), only inspect build-system
                 configuration files.
    """

    #: Short, unique identifier for this detector (used in log messages).
    name: str = "base"

    def __init__(self, path: Path, *, deep: bool = False) -> None:
        self._path = path
        self._deep = deep

    @abc.abstractmethod
    def detect(self) -> list[DetectorFinding]:
        """Execute detection and return a list of findings.

        Implementations must be side-effect free (read-only) and should
        handle all internal exceptions gracefully, returning an empty list
        rather than raising.
        """

    # ------------------------------------------------------------------
    # Protected helpers available to all subclasses
    # ------------------------------------------------------------------

    def _file_exists(self, *relative_paths: str) -> Path | None:
        """Return the first *relative_path* that exists under the project root.

        :param relative_paths: One or more paths relative to the project root.
        :returns: The first existing :class:`~pathlib.Path`, or ``None``.
        """
        for rel in relative_paths:
            candidate = self._path / rel
            if candidate.exists():
                return candidate
        return None

    def _find_files(self, pattern: str) -> list[Path]:
        """Recursively find files matching *pattern* under the project root.

        :param pattern: A glob pattern (e.g. ``"*.service"``).
        :returns: A list of matching :class:`~pathlib.Path` objects.
        """
        return list(self._path.rglob(pattern))

    def _read_text(self, path: Path) -> str:
        """Read a file as text, returning an empty string on any error."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _grep(self, path: Path, pattern: str) -> list[tuple[int, str]]:
        """Return (line_number, line) pairs matching *pattern* in *path*.

        Line numbers are 1-indexed to match editor conventions.

        :param path: File to search.
        :param pattern: Regular expression pattern.
        :returns: List of ``(line_no, line)`` tuples for matching lines.
        """
        compiled = re.compile(pattern)
        matches: list[tuple[int, str]] = []
        for lineno, line in enumerate(self._read_text(path).splitlines(), start=1):
            if compiled.search(line):
                matches.append((lineno, line))
        return matches


class DetectorRegistry:
    """Registry and orchestrator for :class:`BaseDetector` subclasses.

    Usage::

        # Register a detector class (can also be used as a decorator):
        registry.register(MyDetector)

        # Run all registered detectors against a path:
        findings = registry.run_all(Path("/my/repo"), deep=True)
    """

    def __init__(self) -> None:
        self._detector_classes: list[type[BaseDetector]] = []

    def register(
        self, detector_cls: type[BaseDetector]
    ) -> type[BaseDetector]:
        """Register *detector_cls* and return it (decorator-compatible).

        :param detector_cls: A :class:`BaseDetector` subclass to register.
        :returns: The unchanged *detector_cls*.
        """
        self._detector_classes.append(detector_cls)
        return detector_cls

    def run_all(self, path: Path, *, deep: bool = False) -> list[DetectorFinding]:
        """Instantiate and run every registered detector.

        :param path: Repository root to analyse.
        :param deep: Pass ``True`` to enable exhaustive source scanning.
        :returns: Combined list of :class:`~snapcraft.analyze.models.DetectorFinding`
            objects from all detectors.
        """
        findings: list[DetectorFinding] = []
        for cls in self._detector_classes:
            detector = cls(path, deep=deep)
            findings.extend(detector.detect())
        return findings

    @property
    def detector_names(self) -> list[str]:
        """Return the names of all registered detectors."""
        return [cls.name for cls in self._detector_classes]


#: Global registry instance — import and call ``.register`` to add detectors.
registry = DetectorRegistry()

# Import detector modules so their @registry.register decorators fire.
# Keep this at the bottom to avoid circular imports.
from snapcraft.analyze.detectors import (  # noqa: E402, F401
    build_systems,
    docker,
    systemd,
    ubuntu_frame,
)
