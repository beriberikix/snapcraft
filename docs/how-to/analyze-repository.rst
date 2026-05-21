.. meta::
    :description: How to use snapcraft analyze to inspect a repository for snap packaging readiness, interpret the output, and generate a snapcraft.yaml scaffold or AI agent prompt.

.. _how-to-analyze:

Analyze a repository for snap packaging
========================================

The ``snapcraft analyze`` command inspects a local repository and reports on
its readiness for packaging as a snap.  It targets projects that run as
headless daemons, background services, and graphical applications deployed via
`Ubuntu Frame <https://ubuntu.com/frame>`_ on Ubuntu Core IoT devices.

The command is read-only: it never modifies the repository.


What the command produces
--------------------------

For every repository it analyses, ``snapcraft analyze`` produces:

- **Build-system identification** — detects the language ecosystem and maps
  it to the correct Snapcraft plugin (``go``, ``python``, ``cmake``, etc.).
- **Daemon configuration hints** — reads ``*.service`` files and infers the
  ``daemon:`` type, restart condition, and required interface plugs.
- **Interface plug recommendations** — infers which snap interfaces the
  application needs (``network``, ``serial-port``, ``gpio``, etc.).
- **Strict-confinement warnings** — flags hardcoded absolute paths
  (``/etc/``, ``/var/lib/``, ``/usr/bin/``) and ``USER root`` directives that
  will be denied inside a strictly confined snap.
- **A best-effort** ``snap/snapcraft.yaml`` **scaffold** — a complete YAML
  file with ``TODO`` markers for any fields that could not be determined
  automatically.  For Ubuntu Frame apps the scaffold applies the full
  ``gpu-2404`` content interface + ``wayland-launch`` command-chain template.
- **AI action items** — structured metadata (available via ``--format json``)
  describing every blocker and gap so that a downstream AI agent can act on
  each finding without re-reading the repository.


Prerequisites
--------------

- Snapcraft installed from the Snap Store (``snap install snapcraft --classic``)
  **or** installed in an editable Python virtual environment (see
  :ref:`how-to-analyze-local-dev` below).
- A local Git repository to analyse.


Analyse a repository
---------------------

Run the command from any directory, passing the path to the repository:

.. code-block:: bash

    snapcraft analyze /path/to/my-repo

Or analyse the current directory:

.. code-block:: bash

    snapcraft analyze .

The default output is a human-readable report printed to the terminal.


Use JSON output for scripting or AI agents
-------------------------------------------

Pass ``--format json`` to receive the full
:class:`~snapcraft.analyze.models.AnalysisReport` as indented JSON on
standard output.  This is the intended interface for downstream AI migration
agents:

.. code-block:: bash

    snapcraft analyze . --format json

    # Pipe to jq for querying specific sections:
    snapcraft analyze . --format json | jq '.ai_actions'
    snapcraft analyze . --format json | jq '.scaffold.yaml_content'
    snapcraft analyze . --format json | jq '.confinement_warnings'

The JSON schema mirrors the Pydantic models defined in
``snapcraft/analyze/models.py``.


Generate an AI coding agent prompt
------------------------------------

Pass ``--format prompt`` to emit a self-contained Markdown prompt on standard
output.  The prompt is agent-agnostic and can be pasted into any AI coding
agent (Claude, Copilot, Cursor, etc.).  It instructs the agent to:

1. Install the ``snapcraft-packaging`` skill for domain-specific knowledge.
2. Review the key analysis findings (project type, build system, daemons,
   required interfaces, and confinement issues).
3. Develop the draft ``snapcraft.yaml`` scaffold (embedded in the prompt,
   clearly marked as a starting point requiring further work).
4. Build, install, and smoke-test the snap.
5. Tighten confinement from ``devmode`` to ``strict``.
6. Publish to the Snap Store.

.. code-block:: bash

    snapcraft analyze . --format prompt

    # Save to a file and open in an editor before pasting:
    snapcraft analyze . --format prompt > snap-packaging-prompt.md

The prompt is regenerated from scratch each time; re-run after making
significant changes to the project to get an updated plan.


Enable deep source scanning
----------------------------

By default the command inspects only build-configuration files
(``go.mod``, ``CMakeLists.txt``, ``pyproject.toml``, ``*.service``, etc.).
Pass ``--deep`` to also scan every source file for hardcoded absolute paths
and Wayland/EGL usage:

.. code-block:: bash

    snapcraft analyze . --deep

.. note::

   Deep scanning can be slow on large repositories.  Reserve it for the
   final readiness check before packaging.


Interpret the output
---------------------

Build System
   The detected language ecosystem and Snapcraft plugin.  If multiple build
   systems are found (e.g. a ``CMakeLists.txt`` alongside a ``Makefile``),
   the detector with higher confidence wins.

Ubuntu Frame (IoT GUI)
   Shown only when Qt, GTK, Flutter, SDL2, Electron, or native Wayland usage
   is detected.  The scaffold switches to the ``gpu-2404`` content interface
   template automatically.

Daemons
   Each ``*.service`` file found in the repository appears here with its
   mapped ``daemon:`` type (``simple``, ``forking``, ``oneshot``, ``notify``),
   restart condition, and any hardware plugs inferred from the
   ``ExecStart=`` path.

Inferred Interface Plugs
   Snap interfaces the application will need.  ``auto-connect`` interfaces
   are granted automatically after installation; ``manual connect`` ones
   require ``snap connect`` or a Brand Store assertion.

Confinement Warnings
   Each warning shows the file and line number where the issue was found,
   a description, and a suggested fix.  Treat ``[ERROR]`` items as blockers
   that will cause AppArmor ``DENIED`` entries; ``[WARNING]`` items are
   likely problems.

Generated snap/snapcraft.yaml
   A best-effort scaffold.  Search for ``TODO`` to find fields that need
   manual completion.  The confidence percentage reflects how much
   information was available during analysis.

AI Action Items
   A machine-readable list of every gap and blocker.  When ``--format json``
   is used, the ``ai_actions`` array is the primary input for an AI
   migration agent.


Scaffold confidence guide
--------------------------

============  ================================================================
Confidence    What it means
============  ================================================================
90 – 100 %    Build system, entry points, and daemon config fully detected.
              The scaffold is likely correct with minor metadata changes.
70 – 89 %     Some gaps remain (e.g. entry point could not be determined).
              Review all ``TODO`` markers before building.
< 70 %        Significant information is missing.  The scaffold is a starting
              point only; manual editing is required.
============  ================================================================


.. _how-to-analyze-local-dev:

Set up a local development environment
----------------------------------------

To work on ``snapcraft analyze`` itself — or to run the command from a
development checkout without conflicting with the system-wide snap-installed
Snapcraft — use an editable virtual environment:

.. code-block:: bash

    git clone https://github.com/<your-fork>/snapcraft.git
    cd snapcraft

    python3 -m venv venv
    source venv/bin/activate

    # Install Snapcraft and its development dependencies in editable mode.
    pip install -e '.[dev]'

    # Run the command directly:
    snapcraft analyze /path/to/repo
    snapcraft analyze /path/to/repo --format json | jq .

    # Run the analyze test suite:
    pytest tests/unit/analyze/ tests/unit/commands/test_analyze.py -v

The ``venv`` entry point takes precedence over the system snap, so there is
no conflict.


Add a new detector
-------------------

The heuristic engine is modular.  To add support for a new language or tool:

1. Create a module under ``snapcraft/analyze/detectors/``.
2. Subclass :class:`~snapcraft.analyze.detectors.BaseDetector` and set a
   unique :attr:`name` attribute.
3. Implement :meth:`detect` to return a list of
   :class:`~snapcraft.analyze.models.DetectorFinding` objects.
4. Decorate the class with ``@registry.register``.
5. Import the module at the bottom of
   ``snapcraft/analyze/detectors/__init__.py``.

Minimal example:

.. code-block:: python

    # snapcraft/analyze/detectors/my_language.py
    from snapcraft.analyze.detectors import BaseDetector, registry
    from snapcraft.analyze.models import (
        BuildSystemInfo, DetectorFinding, FindingCategory, Severity,
    )

    @registry.register
    class MyLanguageDetector(BaseDetector):
        name = "my-language"

        def detect(self) -> list[DetectorFinding]:
            sentinel = self._file_exists("my-build-file.cfg")
            if sentinel is None:
                return []

            info = BuildSystemInfo(
                name="MyLanguage",
                plugin="nil",          # replace with real plugin
                entry_points=["bin/myapp"],
            )
            return [DetectorFinding(
                category=FindingCategory.BUILD_SYSTEM,
                severity=Severity.INFO,
                description=f"Detected MyLanguage project (plugin: nil)",
                metadata=info.model_dump(),
            )]

Then add a line to ``detectors/__init__.py``:

.. code-block:: python

    from snapcraft.analyze.detectors import my_language  # noqa: F401
