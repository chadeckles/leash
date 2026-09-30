"""Protection levels and on/off switches for groups of bundled rules.

Rules in the bundled presets carry a ``group:`` tag.  ``~/.leash/settings.yaml``
records a protection level and which groups are switched on; the hook runner
skips rules whose group is switched off.  Rules without a group (your own
``leash allow`` exceptions, the final "allow routine work" rule) always apply.

The file is written by ``leash setup`` and ``leash settings`` and, like the
rest of ``~/.leash``, agents are blocked from changing it.  If it is missing
Leash uses the Balanced level; if it is unreadable Leash turns every group on
(fail closed) and ``leash doctor`` reports it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Optional

from leash import paths


@dataclass(frozen=True)
class Group:
    id: str
    title: str
    detail: str
    locked: bool = False


GROUPS = (
    Group("tamper", "Protect Leash itself",
          "Agents can't turn Leash off, edit its rules or approve their own exceptions.", locked=True),
    Group("secrets", "Block access to passwords and keys",
          "SSH keys, cloud credentials, .env files, browser and password stores."),
    Group("destructive", "Block destructive commands",
          "rm -rf ~, disk wipes, curl | sh, deleting repositories."),
    Group("production", "Protect databases and cloud resources",
          "DROP/TRUNCATE, database resets, terraform destroy, deleting clusters and cloud resources."),
    Group("risky", "Ask before risky actions",
          "sudo, force-push, publishing packages, terraform apply, kubectl delete."),
    Group("untrusted", "Ask before acting on untrusted content",
          "After the agent reads web pages or MCP results, ask before it pushes, posts or sends anything."),
    Group("outside_workspace", "Ask before changing files outside the project",
          "Writing or deleting files outside the folder the agent was started in."),
    Group("network", "Ask before downloading or installing",
          "Web fetches, curl/wget, git clone, npm/pip/brew installs."),
)
GROUP_IDS = tuple(g.id for g in GROUPS)
_ALL = frozenset(GROUP_IDS)

LEVELS: Dict[str, FrozenSet[str]] = {
    "strict": _ALL,
    "balanced": _ALL - {"network"},
    "relaxed": frozenset({"tamper", "secrets", "destructive", "production"}),
}
LEVEL_INFO = {
    "strict": "Everything in Balanced, plus ask before downloading or installing anything.",
    "balanced": "Block secrets and destructive commands; ask before risky actions. Recommended.",
    "relaxed": "Only block secrets, destructive commands and production damage; don't ask before risky actions.",
}
DEFAULT_LEVEL = "balanced"


@dataclass
class Settings:
    level: str = DEFAULT_LEVEL
    groups: Dict[str, bool] = field(default_factory=lambda: {g: g in LEVELS[DEFAULT_LEVEL] for g in GROUP_IDS})
    problem: Optional[str] = None

    @property
    def disabled(self) -> FrozenSet[str]:
        return frozenset(g for g, on in self.groups.items() if not on and g != "tamper")

    @property
    def label(self) -> str:
        return self.level.capitalize() if self.level in LEVELS else "Custom"


def settings_file() -> Path:
    return paths.leash_home() / "settings.yaml"


def for_level(level: str) -> Settings:
    if level not in LEVELS:
        raise ValueError(f"Unknown level '{level}'. Choose one of: {', '.join(LEVELS)}")
    return Settings(level, {g: g in LEVELS[level] for g in GROUP_IDS})


def level_for(groups: Dict[str, bool]) -> str:
    on = frozenset(g for g in GROUP_IDS if groups.get(g, True))
    return next((name for name, members in LEVELS.items() if members == on), "custom")


def load(path: Optional[Path] = None) -> Settings:
    import yaml

    path = Path(path or settings_file())
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Settings()
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return Settings("strict", {g: True for g in GROUP_IDS}, f"can't read {path}: {exc}")
    if doc is None:
        return Settings()
    if not isinstance(doc, dict) or not isinstance(doc.get("groups", {}), dict):
        return Settings("strict", {g: True for g in GROUP_IDS}, f"{path} is not a settings file")
    level = str(doc.get("level") or DEFAULT_LEVEL)
    base = LEVELS.get(level, LEVELS[DEFAULT_LEVEL])
    groups = {g: g in base for g in GROUP_IDS}
    for g, on in (doc.get("groups") or {}).items():
        if g in groups:
            groups[g] = on is not False
    groups["tamper"] = True
    return Settings(level_for(groups), groups)


def save(settings: Settings, path: Optional[Path] = None) -> Path:
    import yaml

    path = Path(path or settings_file())
    groups = dict(settings.groups, tamper=True)
    doc = {"level": level_for(groups), "groups": groups}
    header = (
        "# Leash protection settings. Change them with `leash settings`.\n"
        "# level: strict | balanced | relaxed | custom\n"
        "# groups: switch bundled rule groups on (true) or off (false).\n"
        "#   tamper is always on.\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(header + yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    tmp.replace(path)
    return path


def disabled_groups() -> FrozenSet[str]:
    return load().disabled
