"""Shared test helpers. Every test runs offline: network answers come from fixtures."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from core.llm import BaseLLM
from core.net import FixtureNet

ROOT = Path(__file__).resolve().parent.parent
SCENARIO = ROOT / "evals" / "golden" / "training_scenario.json"
T = "demo-corp.example"


@pytest.fixture
def scenario() -> dict:
    """A fresh copy of the training scenario, safe to modify in a test."""
    return copy.deepcopy(json.loads(SCENARIO.read_text()))


@pytest.fixture
def net(scenario) -> FixtureNet:
    return FixtureNet(scenario)


class ScriptedLLM(BaseLLM):
    """Fake LLM for tests: returns queued replies (strings or dicts) in order.

    A reply can also be a function of the payload, so a test can answer
    differently per host. When the queue is empty it falls back to the
    agent's heuristic, like the offline LLM.
    """

    model = "scripted"

    def __init__(self, replies=None):
        self.replies = list(replies or [])
        self.prompts: list[tuple[str, str]] = []

    def _complete(self, system, user, payload, fallback, effort):
        self.prompts.append((system, user))
        if not self.replies:
            return json.dumps(fallback(payload)), 10, 5
        reply = self.replies.pop(0)
        if callable(reply):
            reply = reply(payload)
        return (reply if isinstance(reply, str) else json.dumps(reply)), 10, 5
