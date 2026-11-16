#!/usr/bin/env python3
"""End-to-end SuperPMI CLI ingress smoke test on owned Linux/macOS runners.

Uses the real source-controlled superpmi.py CLI, but harmless local stub
tools and an empty .dll. The expected collection later fails because no
real .mc/JIT output is produced; the test checks the earlier filename boundary.
No privileged capabilities, network targets or external assets are involved.
"""
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr/scripts/superpmi.py"
SIGNAL = "CORECLR14_FULL_CLI_MARKER"


def smoke(root, filename, expected):
    root.mkdir()
    core = root / "core"
    core.mkdir()
    artifacts = root / "assemblies"
    artifacts.mkdir()
    (artifacts / filename).touch()

    # These tools implement no application/JIT execution. Only the vulnerable
    # subprocess-shell boundary under the real CLI is being exercised.
    runner = core / "corerun"
    runner.write_text("#!/usr/bin/env python3\nimport sys\nprint('PMI_STUB', sys.argv[1:])\n")
    runner.chmod(0o755)
    for program in ("mcs", "superpmi"):
        tool = core / program
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o755)
    for artifact in ("pmi.dll", "libclrjit.so", "libclrjit.dylib",
                     "libsuperpmi-shim-collector.so",
                     "libsuperpmi-shim-collector.dylib"):
        (core / artifact).touch()

    args = [
        sys.executable, str(SCRIPT), "collect", "--pmi",
        "-assemblies", str(artifacts),
        "-pmi_location", str(core / "pmi.dll"),
        "-core_root", str(core),
        "-spmi_location", str(root / "spmi"),
        "-output_mch_path", str(root / "out.mch"),
        "-log_level", "DEBUG",
    ]
    result = subprocess.run(
        args, cwd=str(root), capture_output=True, text=True, timeout=45
    )
    marker_file = root / "pmi_cli_marker.txt"
    observed = marker_file.exists() and marker_file.read_text().strip() == SIGNAL
    if observed != expected:
        print("COMMAND", json.dumps(args))
        print("STDOUT", result.stdout[-6000:])
        print("STDERR", result.stderr[-6000:])
        raise AssertionError(
            f"source-controlled CLI marker expected={expected}, actual={observed}, "
            f"rc={result.returncode}"
        )
    return {"filename_type": "crafted" if expected else "ordinary",
            "marker_created": observed,
            "cli_exit_code": result.returncode,
            "failure_expected_after_stub": True}


def main():
    if os.name == "nt":
        print("Windows full CLI test intentionally skipped; AST and subprocess sink are tested in matrix")
        return
    if not SCRIPT.exists():
        raise FileNotFoundError(SCRIPT)
    with tempfile.TemporaryDirectory(prefix="clr14_full_cli_") as temp:
        root = Path(temp)
        # Only a temporary marker inside the test sandbox is written.
        clean = smoke(root / "control", "normal.dll", False)
        attack_name = "probe; echo " + SIGNAL + " > pmi_cli_marker.txt; #.dll"
        injected = smoke(root / "crafted", attack_name, True)
        print(json.dumps({
            "platform": platform.platform(),
            "source": str(SCRIPT.relative_to(ROOT)),
            "normal": clean,
            "crafted": injected,
            "result": "full-cli-collect-pmi-reaches-OS-command-boundary",
        }, indent=2))
        print("SUCCESS: real superpmi.py CLI triggered the isolated marker")


if __name__ == "__main__":
    main()
