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

"""Unit tests for :mod:`snapcraft.analyze.confinement`."""


from snapcraft.analyze.confinement import build_confinement_warnings


class TestPrivilegedSocketDeduplication:
    """Bug fix: /var/run/docker.sock must not produce two warnings."""

    def test_var_run_docker_sock_single_warning(self, tmp_path):
        """A file referencing /var/run/docker.sock should produce exactly one warning."""
        src = tmp_path / "main.py"
        src.write_text('SOCK = "/var/run/docker.sock"\n')
        warnings, actions = build_confinement_warnings([], tmp_path, deep=True)
        socket_warnings = [
            w for w in warnings if w.violation_type == "privileged-socket"
        ]
        assert len(socket_warnings) == 1, (
            f"Expected 1 socket warning, got {len(socket_warnings)}: "
            f"{[w.description for w in socket_warnings]}"
        )

    def test_bare_run_docker_sock_still_detected(self, tmp_path):
        """/run/docker.sock (without /var prefix) must still be flagged."""
        src = tmp_path / "main.go"
        src.write_text('const sock = "/run/docker.sock"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        socket_warnings = [
            w for w in warnings if w.violation_type == "privileged-socket"
        ]
        assert len(socket_warnings) == 1

    def test_containerd_sock_detected(self, tmp_path):
        src = tmp_path / "daemon.go"
        src.write_text('var addr = "/run/containerd.sock"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        socket_warnings = [
            w for w in warnings if w.violation_type == "privileged-socket"
        ]
        assert len(socket_warnings) == 1


class TestHardcodedPathInStringLiteral:
    """Bug fix: hardcoded-path pattern must match paths inside string literals."""

    def test_path_in_python_string_literal(self, tmp_path):
        """/var/log/... inside a double-quoted Python string must be flagged."""
        src = tmp_path / "config.py"
        src.write_text('LOG_PATH = "/var/log/myapp/app.log"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        path_warnings = [
            w for w in warnings if w.violation_type == "hardcoded-path"
        ]
        assert len(path_warnings) >= 1, "Expected hardcoded-path warning for /var/log/..."

    def test_path_in_var_lib_detected(self, tmp_path):
        src = tmp_path / "store.go"
        src.write_text('dataDir := "/var/lib/myapp"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        path_warnings = [
            w for w in warnings if w.violation_type == "hardcoded-path"
        ]
        assert len(path_warnings) >= 1

    def test_safe_etc_paths_not_flagged(self, tmp_path):
        """/etc/hosts, /etc/resolv.conf, etc. are safe and must not be flagged."""
        src = tmp_path / "net.py"
        src.write_text(
            'hosts = open("/etc/hosts").read()\n'
            'rc = open("/etc/resolv.conf").read()\n'
            'tz = open("/etc/timezone").read()\n'
        )
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        path_warnings = [
            w for w in warnings if w.violation_type == "hardcoded-path"
        ]
        assert len(path_warnings) == 0, (
            f"Safe /etc paths should not be flagged: "
            f"{[w.description for w in path_warnings]}"
        )

    def test_usr_bin_path_detected(self, tmp_path):
        src = tmp_path / "runner.sh"
        src.write_text('exec /usr/bin/myapp "$@"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=True)
        path_warnings = [
            w for w in warnings if w.violation_type == "hardcoded-path"
        ]
        assert len(path_warnings) >= 1

    def test_no_warnings_in_shallow_mode(self, tmp_path):
        """Source-file scanning only happens with deep=True."""
        src = tmp_path / "main.py"
        src.write_text('LOG = "/var/log/myapp.log"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=False)
        assert warnings == []
