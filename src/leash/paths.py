"""Filesystem locations for Leash state.

Everything lives under a single home directory, like ``~/.claude`` or
``~/.copilot``:

    ~/.leash/
      policies/      YAML policies (seeded from the bundled presets)
      keys/          server signing keys + admin.key
      leash.db       server database
      token.json     CLI identity

``LEASH_HOME`` overrides the root.  ``POLICIES_DIR``, ``KEYS_DIR`` and
``DATABASE_URL`` still override individual locations.

This module must stay dependency-free: it is imported by the CLI, the SDK,
the engine and the server.
"""

from __future__ import annotations

import os
import shutil
from importlib import resources
from pathlib import Path

PRESETS_PACKAGE = "leash.presets"


def leash_home() -> Path:
    return Path(os.getenv("LEASH_HOME") or Path.home() / ".leash").expanduser()


def policies_dir() -> Path:
    return Path(os.getenv("POLICIES_DIR") or leash_home() / "policies").expanduser()


def keys_dir() -> Path:
    return Path(os.getenv("KEYS_DIR") or leash_home() / "keys").expanduser()


def database_url() -> str:
    return os.getenv("DATABASE_URL") or f"sqlite:///{leash_home() / 'leash.db'}"


def token_file() -> Path:
    return leash_home() / "token.json"


def preset_names() -> list[str]:
    return sorted(
        p.name.rsplit(".", 1)[0]
        for p in resources.files(PRESETS_PACKAGE).iterdir()
        if p.name.endswith((".yaml", ".yml"))
    )


def preset_path(name: str):
    """Return a Traversable for a bundled preset (``default`` → default.yaml)."""
    for ext in (".yaml", ".yml"):
        candidate = resources.files(PRESETS_PACKAGE) / f"{name}{ext}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"Unknown preset '{name}'. Available: {', '.join(preset_names())}")


def seed_policies(target: Path | None = None, presets: list[str] | None = None) -> list[Path]:
    """Copy bundled presets into *target* if it doesn't exist yet.

    An existing directory is never touched, so user edits (or a deliberately
    empty directory) are preserved.  Returns the files written.
    """
    target = Path(target or policies_dir())
    if target.exists():
        return []
    target.mkdir(parents=True, exist_ok=True)
    written = []
    for name in presets or preset_names():
        src = preset_path(name)
        dest = target / src.name
        with resources.as_file(src) as src_file:
            shutil.copyfile(src_file, dest)
        written.append(dest)
    return written
