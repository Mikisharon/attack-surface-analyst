import json
from types import SimpleNamespace

from pydantic import BaseModel

from core.llm import ClaudeLLM, estimate_cost, extract_json, make_llm


class Answer(BaseModel):
    value: int


def fake_client(texts, stop_reason="end_turn"):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        text = texts.pop(0)
        return SimpleNamespace(stop_reason=stop_reason,
                               content=[SimpleNamespace(type="text", text=text)],
                               usage=SimpleNamespace(input_tokens=100, output_tokens=20))
    messages = SimpleNamespace(create=create)
    return SimpleNamespace(messages=messages, beta=SimpleNamespace(messages=messages)), calls


def ask(llm):
    return llm.ask_json(system="s", task="t", payload={"x": 1}, schema=Answer, fallback=lambda p: {})


def test_claude_success_records_tokens_and_uses_fallbacks():
    client, calls = fake_client(['```json\n{"value": 3}\n```'])
    result = ask(ClaudeLLM(model="claude-opus-5-5", client=client))
    assert result.data.value == 3 and result.first_try_valid
    assert (result.input_tokens, result.output_tokens) == (100, 20)
    assert calls[0]["fallbacks"] == "default" and "temperature" not in calls[0]


def test_invalid_json_is_retried_once_with_errors():
    client, calls = fake_client(['nope', '{"value": 4}'])
    result = ask(ClaudeLLM(model="claude-haiku-5-5", client=client))
    assert result.data.value == 4 and result.attempts == 2 and not result.first_try_valid
    assert "rejected" in calls[1]["messages"][0]["content"]
    assert "fallbacks" not in calls[0]


def test_refusal_counts_as_invalid():
    client, _ = fake_client(['', ''], stop_reason="refusal")
    result = ask(ClaudeLLM(model="claude-opus-5-5", client=client))
    assert result.data is None and result.errors


def test_helpers(monkeypatch):
    assert extract_json('noise {"a": 1} noise') == '{"a": 1}'
    assert estimate_cost("claude-opus-5-5", 1_000_000, 0) == 4.0
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert make_llm("auto").model == "offline-heuristic"
