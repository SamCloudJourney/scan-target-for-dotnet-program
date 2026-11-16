#!/usr/bin/env python3
"""CoreCLR #14: actual SuperPMI setup staging -> actual PMI subprocess.

This is an owned-runner, non-destructive evidence test. It AST-extracts actual
staging and PMI functions from the supplied .NET source and uses only temporary
fake CoreRun/PMI assets. It does NOT run Microsoft binaries or target Microsoft
services. Marker output confirms filename shell interpretation after staging.
"""
import ast
import asyncio
import datetime
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
VERSIONS = {
    "dotnet-10.0.15": ROOT / "release-sources/dotnet-10.0.15/runtime/src/coreclr/scripts",
    "dotnet-11.0.100": ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr/scripts",
}
MARKER = "CORECLR14_STAGED_MARKER"


def extract(path, function_names, scope):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in function_names
    ]
    for name in function_names:
        assert sum(node.name == name for node in functions) == 1, (path, name)
    module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
    exec(compile(module, str(path), "exec"), scope)
    return [scope[name] for name in function_names]


def safe_temp_basename(value):
    return re.sub("[^a-zA-Z0-9_.-]", "_", value)[-60:]


async def pmi_run(fn, stub, tmp, assembly):
    tmp.mkdir()
    ctx = SimpleNamespace(corerun=sys.executable, pmi_location=str(stub),
                          temp_location=str(tmp))
    await fn("", str(assembly), ctx)
    outputs = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in tmp.iterdir() if p.suffix in (".stdout", ".stderr")
    )
    return any(x.strip() == MARKER for x in outputs.splitlines())


async def main():
    findings = {"snapshots": {}, "marker": MARKER, "source": "source-extracted setup and run_pmi"}
    with tempfile.TemporaryDirectory(prefix="coreclr14_chain_") as temp:
        base = Path(temp)
        stub = base / "pmi_print.py"
        stub.write_text("import sys\nprint('ARGS', sys.argv[1:])\n", encoding="utf-8")
        for version, folder in VERSIONS.items():
            context = {
                "os": os, "shutil": shutil, "MAX_FILES_COUNT": 1500,
                "native_binaries_to_ignore": [], "asyncio": asyncio,
                "datetime": datetime, "logging": logging, "tempfile": tempfile,
                "make_safe_filename": safe_temp_basename,
                "is_zero_length_file": lambda x: os.path.getsize(x) == 0,
                "write_file_to_log": lambda *args, **kwargs: None,
                "pmi_command_env": dict(os.environ),
            }
            (copy_files,) = extract(folder / "jitutil.py", ["copy_files"], context)
            sorted_files, first_fit, partition_files = extract(
                folder / "superpmi_collect_setup.py",
                ["get_files_sorted_by_size", "first_fit", "partition_files"], context
            )
            (run_pmi,) = extract(folder / "superpmi.py", ["run_pmi"], context)
            src = base / ("input_" + version)
            dst = base / ("partition_" + version)
            (src / "nested").mkdir(parents=True)
            if os.name == "nt":
                candidate_names = [
                    "stage&echo " + MARKER + "&rem .dll",
                    "stage&&echo " + MARKER + "&&rem .exe",
                ]
            else:
                candidate_names = [
                    "stage; echo " + MARKER + "; #.dll",
                    "stage; echo " + MARKER + "; #.exe",
                ]
            filenames = ["normal.dll", "some name with spaces.exe"] + candidate_names
            for filename in filenames:
                (src / "nested" / filename).touch()
            partition_files(str(src), str(dst), 100000, exclude_directories=[],
                            exclude_files=[])
            staged = list(dst.rglob("*"))
            expected = [p for p in staged if p.is_file() and p.suffix in (".dll", ".exe")]
            assert len(expected) == 4, (version, expected)
            results = []
            for i, filename in enumerate(filenames):
                located = [p for p in expected if p.name == filename]
                assert len(located) == 1, (version, filename, located)
                marker = await pmi_run(run_pmi, stub, base / (version + "_" + str(i)), located[0])
                required = i >= 2
                assert marker == required, (version, filename, marker, required)
                results.append({
                    "case": "injected_" + str(i - 2) if required else "clean_" + str(i),
                    "filename_survived_partition": True,
                    "shell_marker_executed": marker,
                })
            findings["snapshots"][version] = {"passed": True, "checks": results}
    print(json.dumps(findings, indent=2))
    print("SUCCESS: actual setup partition_files and copy_files preserve injection into actual run_pmi")


if __name__ == "__main__":
    asyncio.run(main())
