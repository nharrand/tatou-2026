"""Dependency origin and import behavior, separate from protocol tests."""

import json
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

GUARD = Path(__file__).with_name("import_guard.py")
SERVER = Path(__file__).resolve().parents[2]


def test_rmap_manifests_select_git_v2():
    policy = runpy.run_path(str(GUARD))
    dependencies = tomllib.loads((SERVER / "pyproject.toml").read_text())["project"]["dependencies"]
    declared = [line for line in dependencies if line.lower().startswith("rmap")]
    locked = [line for line in (SERVER / "requirements.txt").read_text().splitlines()
              if line.lower().startswith("rmap")]
    assert declared == locked == [policy["RMAP_REQUIREMENT"]]


def test_installed_rmap_provenance_and_import(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(GUARD)], cwd=tmp_path,
        capture_output=True, text=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("origin", [
    {},
    {"url": "https://example.invalid/release.whl"},
    {"url": "https://github.com/nharrand/RMAP.git", "vcs_info": {"vcs": "git", "requested_revision": "v1.0.2"}},
])
def test_provenance_rejects_other_origins(monkeypatch, origin):
    policy = runpy.run_path(str(GUARD))
    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda name: SimpleNamespace(read_text=lambda filename: json.dumps(origin)),
    )
    with pytest.raises(RuntimeError, match=r"Git v2\.0\.0 tag"):
        policy["check_provenance"]()


@pytest.mark.parametrize("payload", [
    "try:\n open(CANARY).read()\nexcept PermissionError:\n pass\n",
    "import socket\ntry:\n socket.create_connection(('127.0.0.1', 9))\nexcept PermissionError:\n pass\n",
    ("import threading, time\ndef worker():\n time.sleep(.05)\n try:\n  open(CANARY).read()\n"
     " except PermissionError:\n  pass\nthreading.Thread(target=worker, daemon=True).start()\n"),
    "import threading\nthreading.Thread(target=lambda: threading.Event().wait(60), daemon=True).start()\n",
], ids=["swallowed-flag-read", "swallowed-network", "background-flag-read", "lingering-thread"])
def test_import_guard_detects_hidden_side_effects(tmp_path, payload):
    flag = tmp_path / "flag"
    flag.write_text("synthetic-only", encoding="utf-8")
    (tmp_path / "synthetic_dependency.py").write_text(f"CANARY = {str(flag)!r}\n" + payload, encoding="utf-8")
    command = (
        "import runpy, sys; sys.path.insert(0, sys.argv[1]); "
        "runpy.run_path(sys.argv[2])['check_import']('synthetic_dependency', sys.argv[3])"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", command, str(tmp_path), str(GUARD), str(flag)],
        cwd=tmp_path, capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode != 0
    assert "Forbidden import side effects" in result.stderr
