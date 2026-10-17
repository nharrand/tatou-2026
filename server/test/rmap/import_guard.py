"""Check RMAP Git provenance and the known import-time leakage pattern.

Run in a fresh process. Audit events and a one-second observation window
are regression checks, not a sandbox against arbitrary native/delayed code.
"""

import importlib
import importlib.metadata
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

RMAP_REPOSITORY = "https://github.com/nharrand/RMAP.git"
RMAP_TAG = "v2.0.0"
RMAP_REQUIREMENT = f"rmap @ git+{RMAP_REPOSITORY}@{RMAP_TAG}"


def check_provenance():
    origin = json.loads(importlib.metadata.distribution("rmap").read_text("direct_url.json") or "{}")
    vcs = origin.get("vcs_info", {})
    if (origin.get("url") != RMAP_REPOSITORY or vcs.get("vcs") != "git"
            or vcs.get("requested_revision") != RMAP_TAG):
        raise RuntimeError("RMAP must be installed from the upstream Git v2.0.0 tag")


def check_import(module, canary):
    """Record attempts even when the imported code swallows exceptions."""
    protected = {Path("/app/flag").resolve(), (Path.cwd() / "flag").resolve(), Path(canary).resolve()}
    violations = []
    forbidden = {
        "socket.connect", "socket.sendto", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }

    def audit(event, args):
        if (event == "open" and isinstance(args[0], (str, bytes, os.PathLike))
                and Path(os.fsdecode(args[0])).resolve() in protected):
            violations.append("flag access")
            raise PermissionError("Flag access forbidden during import")
        if event in forbidden:
            violations.append(event)
            raise PermissionError("Network/process activity forbidden during import")

    previous_threads = set(threading.enumerate())
    sys.addaudithook(audit)
    importlib.import_module(module)
    time.sleep(1.0)
    if set(threading.enumerate()) - previous_threads:
        violations.append("background thread remains active")
    if violations:
        raise RuntimeError(f"Forbidden import side effects: {', '.join(violations)}")


if __name__ == "__main__":
    check_provenance()
    with tempfile.TemporaryDirectory(prefix="rmap-import-") as directory:
        flag = Path(directory) / "flag"
        flag.write_text("synthetic-import-canary", encoding="utf-8")
        check_import("rmap", flag)
    print("RMAP Git v2.0.0 provenance and import behavior OK")
