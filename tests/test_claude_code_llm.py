"""ClaudeCodeLLM: Claude through the Claude Code CLI on a Pro/Max plan.

The CLI is never run here: a fake runner records the command and returns the
JSON that `claude -p --output-format json` prints, so the tests stay offline.
"""
import json
import subprocess

import pytest
from pydantic import BaseModel

from core.llm import ClaudeCodeError, ClaudeCodeLLM, make_llm


class Answer(BaseModel):
    value: int


def completed(stdout, returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def result_json(structured=None, text="", is_error=False):
    data = {"type": "result", "is_error": is_error, "result": text,
            "usage": {"input_tokens": 50, "cache_read_input_tokens": 10, "output_tokens": 7}}
    if structured is not None:
        data["structured_output"] = structured
    return json.dumps(data)


class FakeCLI:
    """Plays `claude`: answers `auth status`, then the queued -p replies in order."""

    def __init__(self, replies, auth_method="claude.ai"):
        self.replies = list(replies)
        self.auth_method = auth_method
        self.calls = []

    def __call__(self, cmd, *, input_text, cwd, env, timeout):
        system_prompt = None
        if "--system-prompt-file" in cmd:
            with open(cmd[cmd.index("--system-prompt-file") + 1], encoding="utf-8") as f:
                system_prompt = f.read()  # read now: the file is deleted after the call
        self.calls.append({"cmd": cmd, "input": input_text, "cwd": cwd, "env": env,
                           "system": system_prompt})
        if cmd[1:3] == ["auth", "status"]:
            return completed(json.dumps({"loggedIn": True, "authMethod": self.auth_method}))
        return self.replies.pop(0)


def make(fake, monkeypatch=None):
    return ClaudeCodeLLM(binary="claude", runner=fake)


def ask(llm):
    return llm.ask_json(system="SKILL TEXT", task="t", payload={"x": 1}, schema=Answer,
                        fallback=lambda p: {})


def test_structured_output_is_used_and_tokens_recorded():
    fake = FakeCLI([completed(result_json(structured={"value": 5}))])
    result = ask(make(fake))
    assert result.data.value == 5 and result.first_try_valid
    assert (result.input_tokens, result.output_tokens) == (60, 7)


def test_command_is_a_tool_free_reasoning_call_on_the_subscription(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
    fake = FakeCLI([completed(result_json(structured={"value": 1}))])
    llm = make(fake)
    ask(llm)
    call = fake.calls[-1]
    cmd = call["cmd"]
    assert cmd[:2] == ["claude", "-p"] and "--bare" not in cmd
    assert cmd[cmd.index("--tools") + 1] == ""                       # no built-in tools
    assert cmd[cmd.index("--disallowedTools") + 1] == "mcp__*"        # no MCP tools
    assert cmd[cmd.index("--model") + 1] == "sonnet"
    assert json.loads(cmd[cmd.index("--json-schema") + 1])["properties"]["value"]
    assert call["system"] == "SKILL TEXT"                             # SKILL.md replaces the default prompt
    assert "<evidence>" in call["input"]                              # evidence goes in on stdin
    assert "ANTHROPIC_API_KEY" not in call["env"]                     # cannot fall back to API billing
    assert all("ANTHROPIC_API_KEY" not in c["env"] for c in fake.calls)
    assert llm.model == "claude-code/sonnet"


def test_falls_back_to_text_when_schema_flag_is_rejected():
    fake = FakeCLI([completed("", returncode=1, stderr="Error: --json-schema is not a valid JSON Schema"),
                    completed(result_json(text='```json\n{"value": 9}\n```'))])
    result = ask(make(fake))
    assert result.data.value == 9
    assert "--json-schema" not in fake.calls[-1]["cmd"]


def test_invalid_answer_is_retried_once_with_errors():
    fake = FakeCLI([completed(result_json(text="not json")),
                    completed(result_json(structured={"value": 2}))])
    result = ask(make(fake))
    assert result.data.value == 2 and result.attempts == 2
    assert "rejected" in fake.calls[-1]["input"]


def test_api_key_login_is_refused():
    with pytest.raises(ClaudeCodeError, match="not a Claude subscription"):
        make(FakeCLI([], auth_method="api_key"))


def test_setup_token_login_is_accepted():
    assert make(FakeCLI([], auth_method="oauth_token")).model.startswith("claude-code/")


def test_cli_error_such_as_usage_limit_stops_the_run():
    fake = FakeCLI([completed(result_json(text="Claude usage limit reached", is_error=True), returncode=1)])
    with pytest.raises(ClaudeCodeError, match="usage limit"):
        ask(make(fake))


def test_missing_cli_gives_install_hint(monkeypatch):
    monkeypatch.delenv("ASA_CLAUDE_BIN", raising=False)
    monkeypatch.setattr("core.llm.shutil.which", lambda name: None)
    with pytest.raises(ClaudeCodeError, match="not installed"):
        ClaudeCodeLLM(runner=FakeCLI([]))


def test_model_can_be_chosen_in_env(monkeypatch):
    monkeypatch.setenv("ASA_CLAUDE_CODE_MODEL", "haiku")
    assert make(FakeCLI([])).model == "claude-code/haiku"


def test_make_llm_claude_code_mode(monkeypatch):
    built = []
    monkeypatch.setattr("core.llm.ClaudeCodeLLM", lambda: built.append(1) or "cc")
    assert make_llm("claude-code") == "cc" and built


def test_cli_reports_missing_claude_code_cleanly(monkeypatch, capsys):
    import run

    monkeypatch.delenv("ASA_CLAUDE_BIN", raising=False)
    monkeypatch.setattr("core.llm.shutil.which", lambda name: None)
    assert run.main(["--demo", "--llm", "claude-code"]) == 2
    assert "Cannot use Claude Code" in capsys.readouterr().out
