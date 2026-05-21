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
from snapcraft.analyze.models import DetectorFinding, FindingCategory, Severity


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

    def test_no_warnings_for_non_python_in_shallow_mode(self, tmp_path):
        """Non-Python source files are not scanned without --deep."""
        src = tmp_path / "main.go"
        src.write_text('dataDir := "/var/lib/myapp"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=False)
        assert warnings == []

    def test_python_source_scanned_in_shallow_mode(self, tmp_path):
        """Python files at project root are scanned even without --deep."""
        src = tmp_path / "main.py"
        src.write_text('LOG = "/var/log/myapp.log"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=False)
        path_warnings = [w for w in warnings if w.violation_type == "hardcoded-path"]
        assert len(path_warnings) >= 1

    def test_python_source_in_subdir_scanned_in_shallow_mode(self, tmp_path):
        """Python files one level deep are scanned without --deep."""
        pkg = tmp_path / "myapp"
        pkg.mkdir()
        (pkg / "config.py").write_text('DATA_DIR = "/var/lib/myapp"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=False)
        path_warnings = [w for w in warnings if w.violation_type == "hardcoded-path"]
        assert len(path_warnings) >= 1

    def test_skip_dirs_not_scanned_in_shallow_mode(self, tmp_path):
        """Directories in _SKIP_DIRS (e.g. .venv) are not scanned shallowly."""
        venv = tmp_path / ".venv"
        venv.mkdir()
        (venv / "site-packages.py").write_text('PATH = "/var/lib/foo"\n')
        warnings, _ = build_confinement_warnings([], tmp_path, deep=False)
        path_warnings = [w for w in warnings if w.violation_type == "hardcoded-path"]
        assert len(path_warnings) == 0


# ---------------------------------------------------------------------------
# New violation type handlers
# ---------------------------------------------------------------------------


class TestNotifyUnverifiedHandler:
    def test_notify_unverified_produces_warning_and_action(self, tmp_path):
        finding = DetectorFinding(
            category=FindingCategory.CONFINEMENT,
            severity=Severity.WARNING,
            description="Type=notify without sd_notify.",
            file="myapp.service",
            metadata={"violation_type": "notify-unverified"},
        )
        warnings, actions = build_confinement_warnings([finding], tmp_path)
        w = next((x for x in warnings if x.violation_type == "notify-unverified"), None)
        assert w is not None
        assert "daemon: simple" in w.suggested_fix or "sdnotify" in w.suggested_fix
        a = next((x for x in actions if x.category == "notify-unverified"), None)
        assert a is not None
        assert "sd_notify" in a.ai_prompt or "sdnotify" in a.ai_prompt


class TestRestartAlwaysHandler:
    def test_restart_always_produces_warning_and_action(self, tmp_path):
        finding = DetectorFinding(
            category=FindingCategory.CONFINEMENT,
            severity=Severity.WARNING,
            description="Restart=always may cause loops.",
            file="myapp.service",
            metadata={"violation_type": "restart-always"},
        )
        warnings, actions = build_confinement_warnings([finding], tmp_path)
        w = next((x for x in warnings if x.violation_type == "restart-always"), None)
        assert w is not None
        assert "on-failure" in w.suggested_fix
        a = next((x for x in actions if x.category == "restart-always"), None)
        assert a is not None
        assert "on-failure" in a.ai_prompt


class TestMissingInitPyHandler:
    def test_missing_init_py_produces_warning_and_action(self, tmp_path):
        finding = DetectorFinding(
            category=FindingCategory.CONFINEMENT,
            severity=Severity.WARNING,
            description="Package 'mypackage/' has no __init__.py.",
            file="mypackage/__init__.py",
            metadata={"violation_type": "missing-init-py", "directory": "mypackage"},
        )
        warnings, actions = build_confinement_warnings([finding], tmp_path)
        w = next((x for x in warnings if x.violation_type == "missing-init-py"), None)
        assert w is not None
        assert "mypackage" in w.suggested_fix
        a = next((x for x in actions if x.category == "missing-init-py"), None)
        assert a is not None
        assert "__init__.py" in a.ai_prompt
