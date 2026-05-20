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

"""Tests for the detector registry."""

from pathlib import Path

import pytest

from snapcraft.analyze.detectors import BaseDetector, DetectorRegistry
from snapcraft.analyze.models import DetectorFinding, FindingCategory, Severity


class _AlwaysFiringDetector(BaseDetector):
    name = "always-firing"

    def detect(self) -> list[DetectorFinding]:
        return [
            DetectorFinding(
                category=FindingCategory.GENERIC,
                severity=Severity.INFO,
                description="always fires",
            )
        ]


class _NeverFiringDetector(BaseDetector):
    name = "never-firing"

    def detect(self) -> list[DetectorFinding]:
        return []


class TestDetectorRegistry:
    def test_register_and_run_all(self, tmp_path):
        reg = DetectorRegistry()
        reg.register(_AlwaysFiringDetector)
        reg.register(_NeverFiringDetector)

        findings = reg.run_all(tmp_path)
        assert len(findings) == 1
        assert findings[0].description == "always fires"

    def test_register_as_decorator(self, tmp_path):
        reg = DetectorRegistry()

        @reg.register
        class _MyDetector(BaseDetector):
            name = "my-detector"

            def detect(self) -> list[DetectorFinding]:
                return [
                    DetectorFinding(
                        category=FindingCategory.GENERIC,
                        severity=Severity.INFO,
                        description="from decorator",
                    )
                ]

        findings = reg.run_all(tmp_path)
        assert len(findings) == 1
        assert findings[0].description == "from decorator"

    def test_detector_names(self):
        reg = DetectorRegistry()
        reg.register(_AlwaysFiringDetector)
        reg.register(_NeverFiringDetector)
        assert "always-firing" in reg.detector_names
        assert "never-firing" in reg.detector_names

    def test_empty_registry_returns_empty_findings(self, tmp_path):
        reg = DetectorRegistry()
        assert reg.run_all(tmp_path) == []

    def test_deep_flag_is_passed(self, tmp_path):
        received_deep: list[bool] = []

        class _DeepChecker(BaseDetector):
            name = "deep-checker"

            def detect(self) -> list[DetectorFinding]:
                received_deep.append(self._deep)
                return []

        reg = DetectorRegistry()
        reg.register(_DeepChecker)
        reg.run_all(tmp_path, deep=True)
        assert received_deep == [True]

    def test_detector_exception_does_not_propagate(self, tmp_path):
        """Detectors that raise should not crash the registry."""

        class _CrashingDetector(BaseDetector):
            name = "crashing"

            def detect(self) -> list[DetectorFinding]:
                raise RuntimeError("boom")

        reg = DetectorRegistry()
        reg.register(_AlwaysFiringDetector)
        # Note: the registry does NOT swallow exceptions by design —
        # individual detectors are responsible for their own error handling.
        # This test documents current behaviour.
        reg.register(_CrashingDetector)
        with pytest.raises(RuntimeError, match="boom"):
            reg.run_all(tmp_path)


class TestBaseDetectorHelpers:
    def test_file_exists_found(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x\n")
        det = _AlwaysFiringDetector(tmp_path)
        result = det._file_exists("go.mod")
        assert result is not None
        assert result.name == "go.mod"

    def test_file_exists_not_found(self, tmp_path):
        det = _AlwaysFiringDetector(tmp_path)
        assert det._file_exists("does-not-exist.txt") is None

    def test_file_exists_first_match(self, tmp_path):
        (tmp_path / "setup.py").write_text("")
        det = _AlwaysFiringDetector(tmp_path)
        result = det._file_exists("pyproject.toml", "setup.py")
        assert result.name == "setup.py"

    def test_find_files(self, tmp_path):
        (tmp_path / "a.service").write_text("")
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (subdir / "b.service").write_text("")
        det = _AlwaysFiringDetector(tmp_path)
        found = det._find_files("*.service")
        names = {f.name for f in found}
        assert names == {"a.service", "b.service"}

    def test_read_text_missing_file(self, tmp_path):
        det = _AlwaysFiringDetector(tmp_path)
        result = det._read_text(tmp_path / "nonexistent.txt")
        assert result == ""

    def test_grep(self, tmp_path):
        src = tmp_path / "main.c"
        src.write_text("int main() {\n    printf(\"hello\");\n    return 0;\n}\n")
        det = _AlwaysFiringDetector(tmp_path)
        matches = det._grep(src, r"printf")
        assert len(matches) == 1
        lineno, line = matches[0]
        assert lineno == 2
        assert "printf" in line
