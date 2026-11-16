#!/usr/bin/env python3
"""Isolated, non-destructive CoreCLR SuperPMI filename-boundary regression.

Loads only the nested run_pmi function AST from the checked-out source snapshots.
Fake corerun/PMI uses a tiny Python argument-printing stub; no .NET binaries,
network access, privileged actions, secrets, or external targets are used.
"""

import ast
import asyncio
import datetime
import hashlib
import json
import logging
import os
import platform
import re
import sys
import tempfile
import urllib.request
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SOURCES = {
    "dotnet-10.0.15": ROOT / "release-sources/dotnet-10.0.15/runtime/src/coreclr/scripts/superpmi.py",
    "dotnet-11.0.100": ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr/scripts/superpmi.py",
}
DISCOVERY_SOURCE = ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr/scripts/jitutil.py"
MARKER = "CORECLR14_RUNNER_MARKER"


def own_log_prefix(value):
    # Corresponds to a safe temporary log prefix; deliberately does not alter
    # the assembly argument, which remains controlled by the source function.
    return re.sub(r"[^a-zA-Z0-9._-]", "_", value)[-70:]


def load_source_function(path, name, async_function):
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    kind = ast.AsyncFunctionDef if async_function else ast.FunctionDef
    nodes = [n for n in ast.walk(tree) if isinstance(n, kind) and n.name == name]
    assert len(nodes) == 1, (path, name, len(nodes))
    node = nodes[0]
    if async_function:
        assert any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "create_subprocess_shell"
            for n in ast.walk(node)
        ), "Upstream sink changed; investigate before relying on the test"

    scope = {
        "asyncio": asyncio,
        "datetime": datetime,
        "logging": logging,
        "os": os,
        "tempfile": tempfile,
        "make_safe_filename": own_log_prefix,
        "is_zero_length_file": lambda p: os.path.getsize(p) == 0,
        "write_file_to_log": lambda *args, **kwargs: None,
        "pmi_command_env": dict(os.environ),
    }
    executable = ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[]))
    exec(compile(executable, filename=str(path), mode="exec"), scope)
    digest = hashlib.sha256(source.encode()).hexdigest()
    return scope[name], digest


def has_marker(logtext):
    return any(line.strip() == MARKER for line in logtext.splitlines())


async def actual_pmi_function_probe(function, stub, directory, assembly):
    directory.mkdir(exist_ok=True)
    context = SimpleNamespace(
        corerun=sys.executable,
        pmi_location=str(stub),
        temp_location=str(directory),
    )
    await function("", str(assembly), context)
    all_logs = []
    for f in sorted(directory.iterdir()):
        if f.name.endswith((".stdout", ".stderr")):
            all_logs.append(f.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(all_logs)


async def argv_boundary_control(stub, assembly):
    proc = await asyncio.create_subprocess_exec(
        sys.executable, str(stub), "DRIVEALL", str(assembly),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    assert proc.returncode == 0, (proc.returncode, err)
    return out.decode("utf-8", errors="replace")


async def main():
    logging.basicConfig(level=logging.WARNING)
    summary = {
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "snapshots": {},
        "control": "argv-based subprocess must not execute a filename",
        "safety": "temporary files and a benign stdout marker only",
    }
    discover, discover_hash = load_source_function(
        DISCOVERY_SOURCE, "get_files_from_path", False
    )
    summary["discovery_sha256"] = discover_hash

    with tempfile.TemporaryDirectory(prefix="coreclr14_") as temp:
        root = Path(temp)
        artifacts = root / "assemblies"
        nested = artifacts / "nested"
        nested.mkdir(parents=True)

        ordinary = nested / "normal.dll"
        plain_text = nested / "not-an-assembly.txt"
        spaced = nested / "name with spaces.dll"
        ordinary.touch()
        plain_text.touch()
        spaced.touch()

        if os.name == "nt":
            candidate_names = [
                prefix + MARKER + suffix + extension
                for extension in (".dll", ".exe")
                for prefix, suffix in (
                    ("probe&echo ", "&rem "),
                    ("probe&&echo ", "&&rem "),
                )
            ]
        else:
            candidate_names = [
                prefix + MARKER + suffix + extension
                for extension in (".dll", ".exe")
                for prefix, suffix in (
                    ("probe; echo ", "; #"),
                    ("probe$(echo ", " 1>&2)"),
                )
            ]
        candidates = []
        for name in candidate_names:
            path = nested / name
            path.touch()
            candidates.append(path)

        selected = discover(str(artifacts),
                            match_func=lambda name: name.endswith((".dll", ".exe")))
        assert str(ordinary) in selected
        assert str(plain_text) not in selected
        assert all(str(path) in selected for path in candidates)

        stub = root / "pmi_stub.py"
        stub.write_text(
            "import json, sys\nprint('ARGS=' + json.dumps(sys.argv[1:]))\n",
            encoding="utf-8",
        )

        # Read a pinned upstream public source commit, not a mutable "main" URL.
        # This exercises the latest official code in addition to archived releases.
        upstream_ref = "a5d7014cefc2a1c8492c66ba3baaf35a3f3819c0"
        upstream_url = ("https://raw.githubusercontent.com/dotnet/runtime/"
                        + upstream_ref + "/src/coreclr/scripts/superpmi.py")
        upstream_file = root / "upstream_superpmi.py"
        with urllib.request.urlopen(upstream_url, timeout=25) as response:
            upstream_file.write_bytes(response.read())
        all_sources = dict(SOURCES)
        all_sources["official-main-2026-11-16"] = upstream_file

        for version, path in all_sources.items():
            function, sha256 = load_source_function(path, "run_pmi", True)
            observations = []
            for index, assembly in enumerate([ordinary, spaced] + candidates):
                case_dir = root / ("logs_" + version + "_" + str(index))
                text = await actual_pmi_function_probe(function, stub, case_dir, assembly)
                marker = has_marker(text)
                expected = assembly in candidates
                observation = {
                    "case": "payload_" + str(index - 2) if expected else
                            ("spaced_control" if assembly == spaced else "ordinary_control"),
                    "discovered": str(assembly) in selected,
                    "shell_marker_as_independent_command": marker,
                    "expected": expected,
                }
                observations.append(observation)
                assert marker == expected, (version, assembly.name, text[:2500])

            for assembly in candidates:
                text = await argv_boundary_control(stub, assembly)
                assert not has_marker(text), "Safer argv call unexpectedly ran marker"
                argsline = next(line for line in text.splitlines() if line.startswith("ARGS="))
                args = json.loads(argsline[len("ARGS="):])
                assert args[-1] == str(assembly)
            summary["snapshots"][version] = {
                "source_sha256": sha256,
                "cases": observations,
                "all_checks_passed": True,
                "argv_controls_passed": len(candidates),
            }

    print(json.dumps(summary, indent=2))
    print("SUCCESS: extracted SuperPMI PMI function executed marker only for crafted filenames")


if __name__ == "__main__":
    asyncio.run(main())
