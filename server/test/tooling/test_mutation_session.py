"""Exercise campaign controls without touching native campaign state or processes."""

import importlib.util
import json
import signal
from pathlib import Path

import pytest


@pytest.fixture
def session(tmp_path, monkeypatch):
    script = next(
        parent / "scripts" / "mutation-session.py"
        for parent in Path(__file__).resolve().parents
        if (parent / "scripts" / "mutation-session.py").is_file()
    )
    spec = importlib.util.spec_from_file_location("mutation_session", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "SERVER", tmp_path)
    monkeypatch.setattr(module, "SESSION", tmp_path / "mutants/.mutation-session.json")
    monkeypatch.setattr(module, "EXECUTABLE", tmp_path / ".venv/bin/mutmut")
    module.discover_runs = module.active_runs
    monkeypatch.setattr(module, "active_runs", dict)
    return module


def test_resume_scoped_campaign_runs_only_unfinished_selected_mutants(session, monkeypatch):
    session.save(["watermarking_methods.francesco.*"])
    metadata = session.SESSION.parent / "sample.meta"
    metadata.write_text(json.dumps({"exit_code_by_key": {
        "watermarking_methods.francesco.__init__.x_pending": None,
        "watermarking_methods.francesco.x_finished": 1,
        "server.x_unrelated": None,
    }}))
    calls = []
    monkeypatch.setattr(session.sys, "argv", ["helper", "resume"])
    monkeypatch.setattr(session.os, "chdir", lambda path: None)
    monkeypatch.setattr(session.os, "execv", lambda *args: calls.append(args))
    session.main()
    assert calls == [(str(session.EXECUTABLE), [
        str(session.EXECUTABLE), "run", "watermarking_methods.francesco.x_pending",
    ])]
    assert json.loads(session.SESSION.read_text())["args"] == ["watermarking_methods.francesco.*"]


@pytest.mark.parametrize("state", ["missing", "invalid", "completed"])
def test_resume_does_not_start_without_pending_results(session, monkeypatch, state):
    if state == "invalid":
        session.save([])
        session.SESSION.write_text("invalid json")
    elif state == "completed":
        session.save([])
        (session.SESSION.parent / "sample.meta").write_text(
            json.dumps({"exit_code_by_key": {"server.x_finished": 1}})
        )
    monkeypatch.setattr(session.sys, "argv", ["helper", "resume"])
    monkeypatch.setattr(session.os, "execv", lambda *args: pytest.fail("Unexpected campaign start"))
    assert session.main() == 0


def test_pause_signals_only_coordinator_and_preserves_results(session, monkeypatch):
    session.save(["server.*"])
    evidence = session.SESSION.parent / "sample.meta"
    evidence.write_text("preserve me")
    runs = iter([{123: ["server.*"]}, {}])
    monkeypatch.setattr(session, "active_runs", lambda: next(runs))
    monkeypatch.setattr(session.sys, "argv", ["helper", "pause"])
    calls = []
    monkeypatch.setattr(session.os, "kill", lambda *args: calls.append(args))
    assert session.main() == 0
    assert calls == [(123, signal.SIGINT)]
    assert evidence.read_text() == "preserve me"


def test_resume_running_campaign_preserves_recorded_scope(session, monkeypatch):
    session.save(["server.*"])
    monkeypatch.setattr(session, "active_runs", lambda: {123: ["server.x_pending"]})
    monkeypatch.setattr(session.sys, "argv", ["helper", "resume"])
    monkeypatch.setattr(session.os, "execv", lambda *args: pytest.fail("Unexpected campaign start"))
    assert session.main() == 0
    assert json.loads(session.SESSION.read_text())["args"] == ["server.*"]


def test_unknown_action_cannot_signal_campaign(session, monkeypatch):
    monkeypatch.setattr(session.sys, "argv", ["helper", "unknown"])
    monkeypatch.setattr(session, "active_runs", lambda: pytest.fail("Unexpected process discovery"))
    assert session.main() == 2


def test_process_discovery_excludes_workers_and_other_checkouts(session, monkeypatch):
    output = (
        f"123 1 python {session.EXECUTABLE} run server.*\n"
        f"124 123 python {session.EXECUTABLE} run server.*\n"
        "125 1 python /another/checkout/.venv/bin/mutmut run\n"
        f"126 1 {session.SERVER / '.venv/bin/python'} .venv/bin/mutmut run server.*\n"
    )
    monkeypatch.setattr(session.subprocess, "check_output", lambda *args, **kwargs: output)
    assert session.discover_runs() == {123: ["server.*"], 126: ["server.*"]}


def test_unfiltered_resume_uses_native_cache(session, monkeypatch):
    session.save([])
    (session.SESSION.parent / "sample.meta").write_text(
        json.dumps({"exit_code_by_key": {"server.x_pending": None, "server.x_finished": 1}})
    )
    calls = []
    monkeypatch.setattr(session.sys, "argv", ["helper", "resume"])
    monkeypatch.setattr(session.os, "chdir", lambda path: None)
    monkeypatch.setattr(session.os, "execv", lambda *args: calls.append(args))
    session.main()
    assert calls == [(str(session.EXECUTABLE), [str(session.EXECUTABLE), "run"])]


def test_pause_without_campaign_has_no_effect(session, monkeypatch):
    monkeypatch.setattr(session.sys, "argv", ["helper", "pause"])
    monkeypatch.setattr(session.os, "kill", lambda *args: pytest.fail("Unexpected signal"))
    assert session.main() == 0
    assert not session.SESSION.exists()


def test_new_campaign_check_refuses_active_coordinator(session, monkeypatch):
    monkeypatch.setattr(session.sys, "argv", ["helper", "check"])
    monkeypatch.setattr(session, "active_runs", lambda: {123: []})
    assert session.main() == 1
    assert not session.SESSION.exists()
