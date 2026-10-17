"""Control this checkout's mutmut campaign without deleting its results."""

import json
import os
import secrets
import shlex
import signal
import subprocess
import sys
import time
from fnmatch import fnmatchcase
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1] / "server"
EXECUTABLE = SERVER / ".venv/bin/mutmut"
SESSION = SERVER / "mutants/.mutation-session.json"


def active_runs():
    output = subprocess.check_output(["ps", "-axo", "pid=,ppid=,command="], text=True)
    matches = {}
    for line in output.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        pid, parent, command = fields
        try:
            args = shlex.split(command)
        except ValueError:
            continue
        executable = str(EXECUTABLE)
        # Also recognize campaigns started by the previous relative-path launcher.
        if executable not in args and str(SERVER / ".venv/bin/python") in args:
            executable = ".venv/bin/mutmut"
        if executable in args:
            index = args.index(executable)
            if args[index + 1:index + 2] == ["run"]:
                matches[int(pid)] = (int(parent), args[index + 2:])
    return {pid: args for pid, (parent, args) in matches.items() if parent not in matches}


def save(args):
    SESSION.parent.mkdir(exist_ok=True)
    temporary = SESSION.with_suffix(".tmp")
    temporary.write_text(json.dumps({"args": args}) + "\n")
    temporary.replace(SESSION)


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"check", "record", "pause", "resume"}:
        print("Internal helper: use make help for supported commands.")
        return 2
    action = sys.argv[1]
    runs = active_runs()
    if action in {"record", "check"}:
        if runs:
            print("A campaign is already running; nothing changed.")
            return 1
        if action == "record":
            save(sys.argv[2:])
        return 0
    if len(runs) > 1:
        print("Multiple campaign coordinators found; nothing changed.")
        return 0
    if runs:
        pid, args = next(iter(runs.items()))
        if not SESSION.is_file():
            save(args)
        if action == "resume":
            print("The campaign is already running; nothing started.")
            return 0
        # SIGINT uses mutmut's own worker cleanup, like Ctrl-C in its terminal.
        try:
            os.kill(pid, signal.SIGINT)
        except ProcessLookupError:
            print("The campaign has already stopped.")
            return 0
        for _ in range(100):
            if pid not in active_runs():
                print("Campaign paused. Saved results are preserved.")
                return 0
            time.sleep(0.1)
        print("Pause requested; mutmut is still shutting down. Do not resume yet.")
        return 0
    if action == "pause":
        print("No campaign is running; nothing changed.")
        return 0
    if not SESSION.is_file():
        print("No recorded session is available; nothing started.")
        return 0
    try:
        args = json.loads(SESSION.read_text())["args"]
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError("invalid arguments")
        metadata = list((SERVER / "mutants").rglob("*.meta"))
        pending = [
            key.replace("__init__.", "")
            for path in metadata
            for key, value in json.loads(path.read_text()).get("exit_code_by_key", {}).items()
            if value is None and (not args or any(fnmatchcase(key.replace("__init__.", ""), pattern) for pattern in args))
        ]
        if not pending:
            print("No unfinished mutants are available; nothing started.")
            return 0
    except (OSError, ValueError, KeyError, TypeError):
        print("Session data is unavailable or invalid; nothing started.")
        return 0
    os.chdir(SERVER)
    os.environ["SECRET_KEY"] = secrets.token_hex(32)
    # Explicit filters make mutmut rerun completed results: select pending IDs only.
    os.execv(str(EXECUTABLE), [str(EXECUTABLE), "run", *(pending if args else [])])


if __name__ == "__main__":
    sys.exit(main())
