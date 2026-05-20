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

"""Tests for the Docker, systemd, and Ubuntu Frame detectors."""

import pytest

from snapcraft.analyze.detectors.docker import DockerDetector
from snapcraft.analyze.detectors.systemd import SystemdDetector
from snapcraft.analyze.detectors.ubuntu_frame import UbuntuFrameDetector
from snapcraft.analyze.models import FindingCategory, Severity


# ===========================================================================
# Docker
# ===========================================================================


class TestDockerDetector:
    def test_no_dockerfile_returns_empty(self, tmp_path):
        assert DockerDetector(tmp_path).detect() == []

    def test_dockerfile_with_go_base(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM golang:1.22\nRUN apt-get install -y git\nCMD [\"/app/server\"]\n"
        )
        findings = DockerDetector(tmp_path).detect()
        plugin_hints = [
            f.metadata.get("plugin_hint")
            for f in findings
            if "plugin_hint" in f.metadata
        ]
        assert "go" in plugin_hints

    def test_expose_triggers_network_bind(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM python:3.12\nEXPOSE 8080\nCMD [\"python\", \"app.py\"]\n"
        )
        findings = DockerDetector(tmp_path).detect()
        network_hints = [
            f for f in findings
            if f.metadata.get("plug_hint") == "network-bind"
        ]
        assert len(network_hints) >= 1

    def test_user_root_emits_error(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:24.04\nUSER root\nCMD [\"bash\"]\n"
        )
        findings = DockerDetector(tmp_path).detect()
        errors = [
            f for f in findings
            if f.metadata.get("violation_type") == "user-root"
        ]
        assert len(errors) == 1
        assert errors[0].severity == Severity.ERROR

    def test_cmd_directive_extracts_command(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM golang:1.22\nCMD [\"/usr/local/bin/myservice\", \"--config\", \"/etc/myservice.conf\"]\n"
        )
        findings = DockerDetector(tmp_path).detect()
        cmd_hints = [
            f.metadata.get("command_hint")
            for f in findings
            if "command_hint" in f.metadata
        ]
        assert any("myservice" in str(h) for h in cmd_hints)

    def test_hardcoded_path_in_deep_mode(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:24.04\nRUN mkdir /etc/myapp\nCMD [\"myapp\"]\n"
        )
        findings = DockerDetector(tmp_path, deep=True).detect()
        path_warnings = [
            f for f in findings
            if f.category == FindingCategory.HARDCODED_PATH
        ]
        assert len(path_warnings) >= 1

    def test_hardcoded_path_not_in_shallow_mode(self, tmp_path):
        (tmp_path / "Dockerfile").write_text(
            "FROM ubuntu:24.04\nRUN mkdir /etc/myapp\nCMD [\"myapp\"]\n"
        )
        findings = DockerDetector(tmp_path, deep=False).detect()
        path_warnings = [
            f for f in findings
            if f.category == FindingCategory.HARDCODED_PATH
        ]
        assert len(path_warnings) == 0

    def test_dockerfile_variant_filename(self, tmp_path):
        (tmp_path / "Dockerfile.prod").write_text(
            "FROM python:3.12\nCMD [\"python\", \"app.py\"]\n"
        )
        findings = DockerDetector(tmp_path).detect()
        assert len(findings) > 0


# ===========================================================================
# Systemd
# ===========================================================================


class TestSystemdDetector:
    def test_no_service_files_returns_empty(self, tmp_path):
        assert SystemdDetector(tmp_path).detect() == []

    def test_simple_service_unit(self, tmp_path):
        (tmp_path / "myapp.service").write_text(
            "[Unit]\nDescription=My App\n\n"
            "[Service]\nType=simple\nExecStart=/usr/bin/myapp\nRestart=on-failure\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        daemon_findings = [
            f for f in findings
            if f.category == FindingCategory.DAEMON
        ]
        assert len(daemon_findings) == 1
        meta = daemon_findings[0].metadata
        assert meta["daemon_type"] == "simple"
        assert meta["restart_condition"] == "on-failure"
        assert meta["command"] == "bin/myapp"

    def test_forking_service(self, tmp_path):
        (tmp_path / "server.service").write_text(
            "[Service]\nType=forking\nExecStart=/usr/sbin/nginx\nRestart=always\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        meta = findings[0].metadata
        assert meta["daemon_type"] == "forking"
        assert meta["restart_condition"] == "always"

    def test_notify_service(self, tmp_path):
        (tmp_path / "notifier.service").write_text(
            "[Service]\nType=notify\nExecStart=/usr/bin/notifyd\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        assert findings[0].metadata["daemon_type"] == "notify"

    def test_user_root_emits_confinement_error(self, tmp_path):
        (tmp_path / "priv.service").write_text(
            "[Service]\nType=simple\nExecStart=/usr/bin/priv\nUser=root\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        confinement_errors = [
            f for f in findings
            if f.category == FindingCategory.CONFINEMENT
        ]
        assert len(confinement_errors) == 1
        assert confinement_errors[0].severity == Severity.ERROR

    def test_multiple_service_files(self, tmp_path):
        for name in ["alpha.service", "beta.service"]:
            (tmp_path / name).write_text(
                "[Service]\nType=simple\nExecStart=/usr/bin/daemon\n"
            )
        findings = SystemdDetector(tmp_path).detect()
        daemon_findings = [f for f in findings if f.category == FindingCategory.DAEMON]
        assert len(daemon_findings) == 2

    def test_service_in_subdirectory(self, tmp_path):
        subdir = tmp_path / "systemd" / "system"
        subdir.mkdir(parents=True)
        (subdir / "myapp.service").write_text(
            "[Service]\nType=simple\nExecStart=/usr/bin/myapp\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        assert len([f for f in findings if f.category == FindingCategory.DAEMON]) == 1

    def test_serial_port_inferred_from_execstart(self, tmp_path):
        (tmp_path / "iot.service").write_text(
            "[Service]\nType=simple\nExecStart=/usr/bin/sensor /dev/ttyUSB0\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        meta = findings[0].metadata
        assert "serial-port" in meta.get("plugs", [])

    def test_daemon_name_derived_from_filename(self, tmp_path):
        (tmp_path / "my-sensor.service").write_text(
            "[Service]\nType=simple\nExecStart=/usr/bin/sensor\n"
        )
        findings = SystemdDetector(tmp_path).detect()
        assert findings[0].metadata["name"] == "my-sensor"


# ===========================================================================
# Ubuntu Frame
# ===========================================================================


class TestUbuntuFrameDetector:
    def test_no_signals_returns_empty(self, tmp_path):
        assert UbuntuFrameDetector(tmp_path).detect() == []

    def test_qt5_cmake_detected(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.16)\n"
            "project(MyKiosk)\n"
            "find_package(Qt5 REQUIRED COMPONENTS Core Widgets Wayland)\n"
        )
        findings = UbuntuFrameDetector(tmp_path).detect()
        frame_marker = next(
            (f for f in findings if f.metadata.get("is_ubuntu_frame_app")), None
        )
        assert frame_marker is not None
        assert "opengl" in frame_marker.metadata["required_plugs"]
        assert "wayland" in frame_marker.metadata["required_plugs"]

    def test_flutter_pubspec_detected(self, tmp_path):
        (tmp_path / "pubspec.yaml").write_text(
            "name: my_kiosk\n"
            "description: A kiosk app\n"
            "dependencies:\n"
            "  flutter:\n"
            "    sdk: flutter\n"
        )
        findings = UbuntuFrameDetector(tmp_path).detect()
        assert any(f.metadata.get("is_ubuntu_frame_app") for f in findings)

    def test_electron_package_json_detected(self, tmp_path):
        import json
        (tmp_path / "package.json").write_text(
            json.dumps({
                "name": "kiosk-electron",
                "dependencies": {"electron": "^28.0.0"},
            })
        )
        findings = UbuntuFrameDetector(tmp_path).detect()
        assert any(f.metadata.get("is_ubuntu_frame_app") for f in findings)

    def test_gtk3_meson_detected(self, tmp_path):
        (tmp_path / "meson.build").write_text(
            "project('myapp', 'c')\n"
            "gtk3 = dependency('gtk+-3.0')\n"
        )
        findings = UbuntuFrameDetector(tmp_path).detect()
        assert any(f.metadata.get("is_ubuntu_frame_app") for f in findings)

    def test_deep_scan_finds_wayland_header(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.c").write_text(
            '#include <stdio.h>\n'
            '#include <wayland-client.h>\n'
            'int main() { return 0; }\n'
        )
        # Shallow scan should NOT find it (no build config).
        findings_shallow = UbuntuFrameDetector(tmp_path, deep=False).detect()
        assert not any(f.metadata.get("is_ubuntu_frame_app") for f in findings_shallow)

        # Deep scan should find it.
        findings_deep = UbuntuFrameDetector(tmp_path, deep=True).detect()
        assert any(f.metadata.get("is_ubuntu_frame_app") for f in findings_deep)

    def test_command_chain_in_metadata(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text(
            "project(kiosk)\nfind_package(Qt6 REQUIRED)\n"
        )
        findings = UbuntuFrameDetector(tmp_path).detect()
        frame_marker = next(
            (f for f in findings if f.metadata.get("is_ubuntu_frame_app")), None
        )
        assert frame_marker is not None
        chain = frame_marker.metadata["command_chain"]
        assert "bin/gpu-2404-wrapper" in chain
        assert "bin/wayland-launch" in chain
