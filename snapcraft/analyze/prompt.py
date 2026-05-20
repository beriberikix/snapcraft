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

"""Prompt generator for ``snapcraft analyze --format prompt``.

Produces a self-contained, agent-agnostic Markdown prompt that an AI coding
agent (or a human developer) can follow to package the analysed project as a
snap from start to publication.

The prompt:

1. Instructs the reader to install the ``snapcraft-packaging`` skill.
2. Summarises the key analysis findings (project type, build system, daemons,
   required interfaces, confinement issues).
3. Embeds the draft ``snapcraft.yaml`` scaffold with explicit caveats that it
   is a starting point requiring further development.
4. Walks through the full workflow: build → install → test → tighten
   confinement → publish.

The template is embedded as a module-level constant so there are no external
data files to package.  Jinja2 is used because the prompt has several
conditional sections (Ubuntu Frame vs daemon vs generic app; optional
confinement-warning and gap blocks) that would be unwieldy with f-strings.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import jinja2

if TYPE_CHECKING:
    from snapcraft.analyze.models import AnalysisReport

# ---------------------------------------------------------------------------
# Jinja2 template
# ---------------------------------------------------------------------------

_SKILL_INSTALL_CMD = (
    "npx skills add canonical/skills-playground --skill snapcraft-packaging"
)

_PROMPT_TEMPLATE = """\
# Snap Packaging Plan for `{{ snap_name }}`

You are an AI coding agent.  Your goal is to package the project at
`{{ project_path }}` as a snap and guide it through to a successful
publication on the Snap Store.

Work through the steps below in order.  Each step builds on the previous one.

---

## Step 1 — Install the snapcraft-packaging skill

Before doing anything else, install the skill that provides snapcraft-specific
knowledge, workflows, and best-practice guidance:

```
{{ skill_install_cmd }}
```

Load and follow that skill throughout this task.

---

## Step 2 — Review the analysis summary

The project has already been analysed by `snapcraft analyze`.  Here are the
key findings:

**Project type:** {{ project_type }}
{% if build_system %}
**Build system:** {{ build_system.name }} (snapcraft plugin: `{{ build_system.plugin }}`\
{% if build_system.version %}, detected version: {{ build_system.version }}\
{% endif %})
{% if build_system.entry_points %}
**Entry points:** {{ build_system.entry_points | join(', ') }}
{% endif %}
{% if build_system.build_packages %}
**Build packages:** {{ build_system.build_packages | join(', ') }}
{% endif %}
{% if build_system.stage_packages %}
**Stage packages:** {{ build_system.stage_packages | join(', ') }}
{% endif %}
{% else %}
**Build system:** None detected — you will need to determine the correct
snapcraft plugin manually by inspecting the repository.
{% endif %}
{% if daemons %}
**Background services (daemons):**
{% for d in daemons %}
- `{{ d.name }}` — type: `{{ d.daemon_type }}`, restart: `{{ d.restart_condition }}`\
{% if d.command %}, command: `{{ d.command }}`{% endif %}
{% if d.source_file %}  (detected from `{{ d.source_file }}`){% endif %}
{% endfor %}
{% endif %}
{% if plugs %}
**Required snap interfaces (plugs):**
{% for p in plugs %}
- `{{ p.name }}` — {{ p.reason }}
{% endfor %}
{% endif %}
{% if confinement_warnings %}
**Confinement issues to resolve ({{ confinement_warnings | length }}):**
{% for w in confinement_warnings %}
- **[{{ w.violation_type | upper }}]**\
{% if w.file %} `{{ w.file }}\
{% if w.line %}:{{ w.line }}{% endif %}`{% endif %} — {{ w.description }}
  *Fix:* {{ w.suggested_fix }}
{% endfor %}
{% endif %}
{% if is_ubuntu_frame_app %}
**Ubuntu Frame (IoT GUI):** This is a graphical application.  The scaffold
uses the `gpu-2404` content interface and `wayland-launch` command-chain
pattern.  Refer to <https://ubuntu.com/frame/docs/24/> for guidance.
{% endif %}

---

## Step 3 — Develop the `snapcraft.yaml`

The `snapcraft.yaml` below was generated automatically by `snapcraft analyze`.
**It is a draft and a starting point only** — treat every field as a
suggestion that requires review and likely further development.

Items marked `TODO` **must** be resolved before the snap will build or run
correctly.  Cross-reference the skill documentation and the
[Snapcraft reference](https://documentation.ubuntu.com/snapcraft/stable/) for
each plugin and interface.
{% if gaps %}
**Known gaps in this draft** (items the analyser could not determine):
{% for gap in gaps %}
- {{ gap }}
{% endfor %}
{% endif %}

```yaml
{{ scaffold_yaml | indent(0) }}
```

---

## Step 4 — Pre-flight checks

Before running `snapcraft`, verify the following:
{% if version_git_no_repo %}
- [ ] **Git repository required** — the scaffold uses `version: git` but no
  `.git` directory was found at `{{ project_path }}`.  Either initialise a
  repository:
  ```
  git init && git add -A && git commit -m "Initial commit"
  ```
  or replace `version: git` with an explicit version string in
  `snapcraft.yaml` (e.g. `version: '1.0.0'`).
{% endif %}
{% if project_in_tmp %}
- [ ] **Move project out of /tmp** — Multipass cannot mount paths outside
  your home directory; `/tmp` paths appear not to exist inside the VM.
  Copy the project first:
  ```
  cp -r {{ project_path }} ~/{{ snap_name }}
  cd ~/{{ snap_name }}
  ```
{% endif %}
- [ ] **Build provider** — Snapcraft defaults to LXD.  If LXD is installed
  but your user is not in the `lxd` group, either fix the membership:
  ```
  sudo usermod -aG lxd $USER && newgrp lxd
  ```
  or force Multipass instead:
  ```
  SNAPCRAFT_BUILD_ENVIRONMENT=multipass snapcraft
  ```

---

## Step 5 — Build the snap

Run snapcraft from the project root (inside a Multipass VM or LXD container if
on a non-Ubuntu host):

```
snapcraft
```

Fix any build errors iteratively.  Common issues:

- Missing `build-packages` — add system libraries needed at compile time.
- Missing `stage-packages` — add runtime libraries the binary links against.
- Wrong `source` path — adjust if the build root is a subdirectory.
- Plugin-specific configuration — consult the skill for plugin-specific keys.

---

## Step 6 — Install and smoke-test
{% if is_headless_daemon %}
Install the snap in devmode and verify the daemon starts:

```
sudo snap install --devmode *.snap
snap services {{ snap_name }}
{% for d in daemons %}
journalctl -u snap.{{ snap_name }}.{{ d.name }} -f
{% endfor %}
```

> **No TTY?** Use `pkexec snap install --devmode *.snap` instead of
> `sudo snap install`.

Check that the service starts, stays running, and produces expected log output.
{% elif is_ubuntu_frame_app %}
Install the snap in devmode and test with Ubuntu Frame:

```
sudo snap install ubuntu-frame
sudo snap install --devmode *.snap
sudo snap set ubuntu-frame daemon=true
```

> **No TTY?** Use `pkexec snap install --devmode *.snap` instead of
> `sudo snap install`.

Verify the application launches and renders correctly in the Frame kiosk.
{% else %}
Install the snap in devmode and run it:

```
sudo snap install --devmode *.snap
snap run {{ snap_name }}
```

> **No TTY?** Use `pkexec snap install --devmode *.snap` instead of
> `sudo snap install`.

Verify the application starts, behaves correctly, and produces no unexpected
errors.
{% endif %}

---

## Step 7 — Tighten confinement

The scaffold starts with `confinement: devmode` so that the snap can run
without interface restrictions during development.  Once the snap works in
devmode, switch to strict confinement:

1. Change `confinement: devmode` → `confinement: strict` and
   `grade: devel` → `grade: stable` in `snapcraft.yaml`.
2. Rebuild: `snapcraft`
3. Install with `--dangerous` (not `--devmode`):
   ```
   sudo snap install --dangerous *.snap
   ```
   > **No TTY?** Use `pkexec snap install --dangerous *.snap`.
4. Run `snappy-debug` in a separate terminal to capture denied syscalls and
   interface accesses:
   ```
   sudo snappy-debug
   ```
5. Add any missing plugs that `snappy-debug` reports and iterate until the
   snap runs cleanly under strict confinement.
{% if confinement_warnings %}
6. Address the confinement issues listed in Step 2 — hardcoded paths and
   root-user assumptions must be fixed for the snap to work in strict mode.
{% endif %}

---

## Step 8 — Publish to the Snap Store

Once the snap passes all tests under strict confinement:

1. Register the snap name (one-time):
   ```
   snapcraft register {{ snap_name }}
   ```
2. Upload and release to the `edge` channel:
   ```
   snapcraft upload --release=edge *.snap
   ```
3. Install from the store to confirm the end-to-end flow:
   ```
   sudo snap install --edge {{ snap_name }}
   ```
4. When ready for wider testing, promote to `beta` then `candidate` then
   `stable` via the Snap Store dashboard or:
   ```
   snapcraft release {{ snap_name }} <revision> stable
   ```

---

*This prompt was generated by `snapcraft analyze --format prompt`.
Re-run the command after making significant changes to the project to
regenerate an updated prompt.*
"""

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_prompt(report: AnalysisReport) -> str:
    """Render the agent prompt from *report*.

    :param report: Completed :class:`~snapcraft.analyze.models.AnalysisReport`.
    :returns: A Markdown string suitable for pasting into any AI coding agent.
    """
    env = jinja2.Environment(  # noqa: S701 — trusted template, no user input
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined,
    )
    template = env.from_string(_PROMPT_TEMPLATE)

    build_system = report.build_systems[0] if report.build_systems else None
    snap_name = _derive_snap_name(report)
    project_type = _derive_project_type(report)
    gaps = report.scaffold.gaps if report.scaffold else []
    scaffold_yaml = report.scaffold.yaml_content if report.scaffold else ""

    # Derive pre-flight booleans from the report.
    # version: git needs a git repo; check directly so we don't parse strings.
    version_git_no_repo = (
        "version: git" in scaffold_yaml
        and not (Path(report.path) / ".git").exists()
    )
    project_in_tmp = report.path.startswith("/tmp")  # noqa: S108

    return template.render(
        snap_name=snap_name,
        project_path=report.path,
        project_type=project_type,
        build_system=build_system,
        daemons=report.daemons,
        plugs=report.plugs,
        confinement_warnings=report.confinement_warnings,
        is_ubuntu_frame_app=report.is_ubuntu_frame_app,
        is_headless_daemon=report.is_headless_daemon,
        gaps=gaps,
        scaffold_yaml=scaffold_yaml,
        skill_install_cmd=_SKILL_INSTALL_CMD,
        version_git_no_repo=version_git_no_repo,
        project_in_tmp=project_in_tmp,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _derive_snap_name(report: AnalysisReport) -> str:
    """Extract the snap name from the scaffold or fall back to the path stem."""
    if report.scaffold:
        # The scaffold YAML starts with "name: <snap-name>\n".
        for line in report.scaffold.yaml_content.splitlines():
            if line.startswith("name:"):
                return line.split(":", 1)[1].strip()
    return Path(report.path).name


def _derive_project_type(report: AnalysisReport) -> str:
    """Produce a human-readable project-type string from *report*."""
    if report.is_ubuntu_frame_app:
        base = "Ubuntu Frame graphical application (IoT kiosk / digital signage)"
    elif report.is_headless_daemon:
        base = "Headless background daemon"
    elif report.build_systems:
        base = f"{report.build_systems[0].name} application"
    else:
        base = "Unknown (no build system detected)"

    if report.build_systems:
        bs = report.build_systems[0]
        if bs.version:
            base += f" — {bs.name} {bs.version}"

    return base
