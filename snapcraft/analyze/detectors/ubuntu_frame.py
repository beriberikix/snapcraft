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

"""Ubuntu Frame / IoT GUI detector for ``snapcraft analyze``.

Identifies projects that are graphical applications suitable for deployment
on Ubuntu Core via Ubuntu Frame (https://ubuntu.com/frame).

Detection is performed at two depths:

* **Shallow** (default): inspects only build-system configuration files
  (CMakeLists.txt, pyproject.toml, package.json, pubspec.yaml, etc.).

* **Deep** (``--deep`` flag): additionally scans C/C++ source and header
  files for Wayland/EGL includes, and searches C/C++ and Python sources for
  Wayland/EGL/X11 client API calls.

When this detector fires it emits findings that tell the scaffold generator
to apply the Ubuntu Frame template pattern:

* ``gpu-2404`` content interface plug (Mesa GPU userspace)
* ``wayland`` and ``opengl`` app plugs
* ``bin/gpu-2404-wrapper`` + ``bin/wayland-launch`` command chain
* Required ``layout:`` entries for ``/usr/share/libdrm``, etc.
* Required ``environment:`` variables (``XDG_*``, ``XKB_CONFIG_ROOT``)
* Both an interactive app entry *and* a ``daemon: simple`` entry
  (the standard Ubuntu Frame dual-app pattern for IoT)

Reference: https://canonical-ubuntu-frame-documentation.readthedocs-hosted.com/
           how-to/packaging-iot-gui/packaging-an-application/
"""

from __future__ import annotations

import re

from snapcraft.analyze.detectors import BaseDetector, registry
from snapcraft.analyze.models import (
    DetectorFinding,
    FindingCategory,
    Severity,
)

# ---------------------------------------------------------------------------
# Toolkit fingerprints — checked against build config files (shallow scan).
# ---------------------------------------------------------------------------

class _Toolkit:
    """Describes one supported UI toolkit and how to identify it."""

    def __init__(
        self,
        name: str,
        display_backend: str,
        stage_packages: list[str],
        env_vars: dict[str, str],
        build_config_patterns: list[tuple[str, str]],
    ) -> None:
        self.name = name
        self.display_backend = display_backend
        self.stage_packages = stage_packages
        self.env_vars = env_vars
        # List of (filename_glob, regex_in_file) pairs.
        self.build_config_patterns = build_config_patterns


_TOOLKITS: list[_Toolkit] = [
    _Toolkit(
        name="Qt5",
        display_backend="wayland",
        stage_packages=["qt5-wayland", "qtwayland5", "libqt5gui5"],
        env_vars={"QT_QPA_PLATFORM": "wayland"},
        build_config_patterns=[
            ("CMakeLists.txt", r"find_package\s*\(\s*Qt5"),
            ("CMakeLists.txt", r"Qt5::Wayland"),
            ("*.pro", r"QT\s*\+=.*wayland"),
            ("*.pro", r"QT\s*\+=.*widgets"),
        ],
    ),
    _Toolkit(
        name="Qt6",
        display_backend="wayland",
        stage_packages=["qt6-wayland", "libqt6gui6"],
        env_vars={"QT_QPA_PLATFORM": "wayland"},
        build_config_patterns=[
            ("CMakeLists.txt", r"find_package\s*\(\s*Qt6"),
            ("CMakeLists.txt", r"Qt6::Wayland"),
        ],
    ),
    _Toolkit(
        name="GTK3",
        display_backend="wayland",
        stage_packages=["libgtk-3-0", "libglib2.0-bin", "librsvg2-common"],
        env_vars={"GDK_BACKEND": "wayland"},
        build_config_patterns=[
            ("CMakeLists.txt", r"pkg_check_modules.*gtk\+-3\.0"),
            ("meson.build", r"dependency\(['\"]gtk\+-3\.0['\"]"),
            ("*.pc", r"gtk\+-3\.0"),
            ("requirements*.txt", r"PyGObject"),
            ("pyproject.toml", r"PyGObject"),
        ],
    ),
    _Toolkit(
        name="GTK4",
        display_backend="wayland",
        stage_packages=["libgtk-4-1", "libglib2.0-bin"],
        env_vars={"GDK_BACKEND": "wayland"},
        build_config_patterns=[
            ("CMakeLists.txt", r"pkg_check_modules.*gtk4"),
            ("meson.build", r"dependency\(['\"]gtk4['\"]"),
        ],
    ),
    _Toolkit(
        name="Flutter",
        display_backend="wayland",
        stage_packages=[],
        env_vars={},
        build_config_patterns=[
            ("pubspec.yaml", r"flutter:"),
            ("pubspec.yaml", r"sdk:\s*flutter"),
        ],
    ),
    _Toolkit(
        name="SDL2",
        display_backend="wayland",
        stage_packages=["libsdl2-2.0-0"],
        env_vars={"SDL_VIDEODRIVER": "wayland"},
        build_config_patterns=[
            ("CMakeLists.txt", r"find_package\s*\(\s*SDL2"),
            ("meson.build", r"dependency\(['\"]sdl2['\"]"),
            ("*.pc", r"sdl2"),
        ],
    ),
    _Toolkit(
        name="Electron",
        display_backend="wayland",
        stage_packages=[],
        env_vars={},
        build_config_patterns=[
            ("package.json", r'"electron"'),
            ("package.json", r'"electron-builder"'),
        ],
    ),
    _Toolkit(
        name="X11/Mir",
        display_backend="x11",
        stage_packages=["mir-x11-kiosk"],
        env_vars={},
        build_config_patterns=[
            ("CMakeLists.txt", r"find_package\s*\(\s*X11"),
            ("meson.build", r"dependency\(['\"]x11['\"]"),
        ],
    ),
]

# Deep-scan patterns for C/C++ source files.
_DEEP_WAYLAND_PATTERNS = [
    r"#include\s*[<\"]wayland-client\.h[>\"]",
    r"#include\s*[<\"]EGL/egl\.h[>\"]",
    r"#include\s*[<\"]GLES2/gl2\.h[>\"]",
    r"wl_display_connect",
    r"wl_compositor_create_surface",
]

_DEEP_X11_PATTERNS = [
    r"#include\s*[<\"]X11/Xlib\.h[>\"]",
    r"XOpenDisplay\s*\(",
]


@registry.register
class UbuntuFrameDetector(BaseDetector):
    """Detect graphical applications suitable for Ubuntu Frame on Ubuntu Core."""

    name = "ubuntu-frame"

    def detect(self) -> list[DetectorFinding]:
        findings: list[DetectorFinding] = []

        for toolkit in _TOOLKITS:
            hit = self._check_toolkit_shallow(toolkit)
            if hit:
                findings.append(hit)

        if self._deep and not findings:
            findings.extend(self._scan_source_deep())

        if findings:
            # Emit the top-level Ubuntu Frame marker finding.
            findings.insert(
                0,
                DetectorFinding(
                    category=FindingCategory.UBUNTU_FRAME,
                    severity=Severity.INFO,
                    description=(
                        "Graphical application detected. "
                        "This project is a candidate for Ubuntu Frame "
                        "(IoT kiosk/display) deployment."
                    ),
                    metadata={
                        "is_ubuntu_frame_app": True,
                        "toolkits": [
                            f["toolkit_name"]
                            for f in [
                                finding.metadata
                                for finding in findings
                                if "toolkit_name" in finding.metadata
                            ]
                        ],
                        # The scaffold generator reads these to apply
                        # the Ubuntu Frame template pattern.
                        "required_plugs": ["opengl", "wayland"],
                        "content_plugs": {
                            "gpu-2404": {
                                "interface": "content",
                                "target": "$SNAP/gpu-2404",
                                "default-provider": "mesa-2404",
                            }
                        },
                        "command_chain": [
                            "bin/gpu-2404-wrapper",
                            "bin/wayland-launch",
                        ],
                        "environment": {
                            "XDG_CACHE_HOME": "$SNAP_USER_COMMON/.cache",
                            "XDG_CONFIG_HOME": "$SNAP_USER_DATA/.config",
                            "XDG_CONFIG_DIRS": "$SNAP/etc/xdg",
                            "XDG_DATA_DIRS": (
                                "$SNAP/usr/local/share:$SNAP/usr/share"
                            ),
                            "XKB_CONFIG_ROOT": "$SNAP/usr/share/X11/xkb",
                        },
                        "layout": {
                            "/usr/share/libdrm": {
                                "bind": "$SNAP/gpu-2404/libdrm"
                            },
                            "/usr/share/drirc.d": {
                                "symlink": "$SNAP/gpu-2404/drirc.d"
                            },
                            "/usr/share/fonts": {
                                "bind": "$SNAP/usr/share/fonts"
                            },
                            "/usr/share/icons": {
                                "bind": "$SNAP/usr/share/icons"
                            },
                            "/etc/fonts": {"bind": "$SNAP/etc/fonts"},
                        },
                    },
                ),
            )

            # Emit a plug hint for wayland-launch setup.
            findings.append(
                DetectorFinding(
                    category=FindingCategory.UBUNTU_FRAME,
                    severity=Severity.INFO,
                    description=(
                        "Ubuntu Frame requires manual interface connection "
                        "during development. Run "
                        "'/snap/<name>/current/bin/setup.sh' after first "
                        "install to connect 'wayland', 'opengl', and "
                        "'gpu-2404' interfaces."
                    ),
                    metadata={"action": "connect-interfaces"},
                )
            )

        return findings

    def _check_toolkit_shallow(
        self, toolkit: _Toolkit
    ) -> DetectorFinding | None:
        """Return a finding if any shallow pattern matches for *toolkit*."""
        for glob_pattern, regex in toolkit.build_config_patterns:
            for candidate in self._path.glob(glob_pattern):
                if candidate.is_file():
                    content = self._read_text(candidate)
                    if re.search(regex, content, re.IGNORECASE):
                        rel = str(candidate.relative_to(self._path))
                        return DetectorFinding(
                            category=FindingCategory.GUI,
                            severity=Severity.INFO,
                            description=(
                                f"{toolkit.name} toolkit detected via "
                                f"'{rel}' (pattern: {regex!r})."
                            ),
                            file=rel,
                            metadata={
                                "toolkit_name": toolkit.name,
                                "display_backend": toolkit.display_backend,
                                "stage_packages": toolkit.stage_packages,
                                "env_vars": toolkit.env_vars,
                            },
                        )
        return None

    def _scan_source_deep(self) -> list[DetectorFinding]:
        """Deep scan: search C/C++ and Python sources for Wayland/EGL/X11 usage."""
        findings: list[DetectorFinding] = []

        source_extensions = [
            "*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp",
            "*.py",
        ]
        for ext in source_extensions:
            for src_file in self._find_files(ext):
                if ".git" in src_file.parts:
                    continue
                for pattern in _DEEP_WAYLAND_PATTERNS:
                    matches = self._grep(src_file, pattern)
                    if matches:
                        lineno, _ = matches[0]
                        rel = str(src_file.relative_to(self._path))
                        findings.append(
                            DetectorFinding(
                                category=FindingCategory.GUI,
                                severity=Severity.INFO,
                                description=(
                                    f"Wayland/EGL usage found in '{rel}' "
                                    f"(pattern: {pattern!r})."
                                ),
                                file=rel,
                                line=lineno,
                                metadata={
                                    "toolkit_name": "Native Wayland",
                                    "display_backend": "wayland",
                                    "stage_packages": [],
                                    "env_vars": {},
                                },
                            )
                        )
                        return findings  # One hit is enough.

                for pattern in _DEEP_X11_PATTERNS:
                    matches = self._grep(src_file, pattern)
                    if matches:
                        lineno, _ = matches[0]
                        rel = str(src_file.relative_to(self._path))
                        findings.append(
                            DetectorFinding(
                                category=FindingCategory.GUI,
                                severity=Severity.INFO,
                                description=(
                                    f"X11/Mir usage found in '{rel}' "
                                    f"(pattern: {pattern!r})."
                                ),
                                file=rel,
                                line=lineno,
                                metadata={
                                    "toolkit_name": "X11/Mir",
                                    "display_backend": "x11",
                                    "stage_packages": ["libx11-6"],
                                    "env_vars": {},
                                },
                            )
                        )
                        return findings  # One hit is enough.

        return findings
