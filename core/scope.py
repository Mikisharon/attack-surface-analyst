"""Scope control (FR-1): refuse any target that is not on the allowlist.

This check runs before any agent, so a typo or an unauthorized domain never
produces a single network request.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
TARGETS_FILE = ROOT / "config" / "targets.yaml"
SOURCES_FILE = ROOT / "config" / "sources.yaml"


class ScopeError(Exception):
    """Raised when a target or host is outside the authorized scope."""


class Target(BaseModel):
    domain: str
    mode: str = "live"  # "live" or "synthetic"
    description: str = ""


def normalize(name: str) -> str:
    return name.strip().lower().rstrip(".")


def load_targets(path: Path = TARGETS_FILE) -> list[Target]:
    data = yaml.safe_load(path.read_text()) or {}
    return [Target(**t) for t in data.get("targets", [])]


def check_target(domain: str, path: Path = TARGETS_FILE) -> Target:
    """Return the allowlisted target, or raise ScopeError."""
    domain = normalize(domain)
    for target in load_targets(path):
        if normalize(target.domain) == domain:
            return target
    raise ScopeError(
        f"'{domain}' is not in {path.name}. Only authorized targets can be scanned."
    )


def in_scope(host: str, target: str) -> bool:
    """A host is in scope if it equals the target or ends with '.<target>'."""
    host, target = normalize(host), normalize(target)
    return host == target or host.endswith("." + target)


def load_sources(path: Path = SOURCES_FILE) -> dict:
    return yaml.safe_load(path.read_text())
