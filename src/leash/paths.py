"""Filesystem locations for Leash state.

Everything lives under a single home directory, like ``~/.claude`` or
``~/.copilot``:

    ~/.leash/
      policies/      YAML policies (seeded from the bundled presets)
      keys/          server signing keys + admin.key
      leash.db       server database
      token.json     CLI identity
      agents/        cached SDK / MCP proxy agent identities
      audit/         local hash-chained decision log (agent hooks)
      state/         hook rate-limit counters and other small state

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


def agents_dir() -> Path:
    return leash_home() / "agents"


def audit_log_file() -> Path:
    return Path(os.getenv("LEASH_AUDIT_LOG") or leash_home() / "audit" / "audit.jsonl").expanduser()


def state_dir() -> Path:
    return leash_home() / "state"


def agent_identity_file(name: str) -> Path:
    """Cached identity for an SDK/proxy/CLI-registered agent."""
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name) or "agent"
    return agents_dir() / f"{safe}.json"


def write_private(path: Path, text: str) -> None:
    """Write *text* to *path* with mode 0600 (created that way, never world-readable)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def preset_names() -> list[str]:
    return sorted(
        p.name.rsplit(".", 1)[0]
        for p in resources.files(PRESETS_PACKAGE).iterdir()
        if p.name.endswith((".yaml", ".yml"))
    )


def preset_path(name: str):
    """Return a Traversable for a bundled preset (``coding-agent`` → coding_agent.yaml)."""
    name = name.replace("-", "_")
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


def install_preset(name: str, target: Path | None = None, *, force: bool = False) -> Path | None:
    """Copy one bundled preset into *target*.  Returns the path written, or
    ``None`` if a file with that name already exists and *force* is false."""
    target = Path(target or policies_dir())
    src = preset_path(name)
    dest = target / src.name
    if dest.exists() and not force:
        return None
    target.mkdir(parents=True, exist_ok=True)
    with resources.as_file(src) as src_file:
        shutil.copyfile(src_file, dest)
    return dest
