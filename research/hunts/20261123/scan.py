#!/usr/bin/env python3
"""Read-only triage of pinned .NET 11 source. Findings are not confirmed."""
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
SCOPE = [
    "scan-target-v11.0.100/src/sdk/src/TemplateEngine",
    "scan-target-v11.0.100/src/sdk/src/Containers",
    "scan-target-v11.0.100/src/nuget-client/src/NuGet.Core/NuGet.Packaging",
    "scan-target-v11.0.100/src/aspnetcore/src/Middleware/HttpOverrides",
    "scan-target-v11.0.100/src/aspnetcore/src/Servers/Kestrel/Core",
    "scan-target-v11.0.100/src/msbuild/src/Build",
]
EXCLUDE = ("/test/", "/tests/", "/obj/", "/bin/", "/generated/", "/samples/", "/ref/")
PATTERNS = [
    ("lexical_path_guard", re.compile(r"\.(?:StartsWith|IndexOf)\s*\("), 12),
    ("archive_entry", re.compile(r"\b(?:ZipArchiveEntry|TarEntry|entry\.FullName|packageFileName)\b"), 12),
    ("shell_process", re.compile(r"\b(?:ProcessStartInfo|Process\.Start|UseShellExecute)\b"), 15),
    ("file_write", re.compile(r"\b(?:File\.(?:Copy|Move|WriteAllText|WriteAllBytes|Create|OpenWrite)|Directory\.CreateDirectory|ExtractToFile|CopyToFile)\s*\("), 12),
    ("permission_or_link", re.compile(r"\b(?:UnixCreateMode|SymbolicLink|LinkTarget|ReparsePoint|FileMode\.Create)\b"), 12),
    ("forwarded_identity", re.compile(r"\b(?:XForwarded|ForwardedHeaders|ITlsConnectionFeature|ClientCertificate)\b"), 12),
]
NEARBY = {
    "lexical_path_guard": (re.compile(r"GetFullPath|Path\.Combine|GetRelativePath|IsSubPathOf"), 14),
    "archive_entry": (re.compile(r"GetFullPath|Path\.Combine|Extract|CopyToFile|CreateDirectory|Unescape"), 12),
    "shell_process": (re.compile(r"\bArguments?\b|ProcessStartInfo|UseShellExecute|/bin/sh|cmd\.exe"), 12),
    "file_write": (re.compile(r"Package|Archive|Extract|Template|RelativePath|TargetPath|destination|symlink|root", re.I), 9),
    "permission_or_link": (re.compile(r"CreateFile|FileStream|Extract|CopyToFile|Delete|Move|Path|UnixCreateMode"), 10),
    "forwarded_identity": (re.compile(r"Request\.Headers|Request\.Scheme|RemoteIpAddress|ClientCertificate|KnownProxies|KnownIPNetworks"), 8),
}
MAX_HITS_PER_FILE = 8

def trim(line):
    return line.strip().replace("\t", " ")[:220]

def main():
    hits, scanned, present = [], 0, []
    for root in SCOPE:
        folder = ROOT / root
        if not folder.exists():
            print("SKIPPED missing root:", root)
            continue
        present.append(root)
        for source in folder.rglob("*.cs"):
            rel = source.relative_to(ROOT).as_posix()
            if any(x in "/" + rel.lower() + "/" for x in EXCLUDE):
                continue
            try:
                lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            scanned += 1
            filehits = 0
            for line_no, line in enumerate(lines):
                if filehits >= MAX_HITS_PER_FILE:
                    break
                for name, needle, span in PATTERNS:
                    if not needle.search(line):
                        continue
                    a = max(0, line_no - span)
                    b = min(len(lines), line_no + span + 1)
                    excerpt = "\n".join(lines[a:b])
                    pair, reward = NEARBY[name]
                    if not pair.search(excerpt):
                        continue
                    guards = [k for k in ("GetFullPath", "GetRelativePath", "IsPathRooted", "StartsWith", "LinkTarget", "Validate", "Check") if k in excerpt]
                    hits.append({
                        "pattern": name, "file": rel, "line": line_no + 1,
                        "code": trim(line), "nearby_guard_strings": guards,
                        "excerpt": "\n".join(f"{i+1}: {trim(lines[i])}" for i in range(max(a, line_no-3), min(b, line_no+4))),
                        "review_score": reward + int(name == "lexical_path_guard" and "GetFullPath" in excerpt) * 3
                                              + int(name == "archive_entry" and ("GetFullPath" in excerpt or "Unescape" in excerpt)) * 2
                                              + int(name == "permission_or_link" and "UnixCreateMode" in excerpt) * 2,
                    })
                    filehits += 1
                    break
    hits.sort(key=lambda h: (-h["review_score"], h["file"], h["line"]))
    counts = dict(sorted(Counter(h["pattern"] for h in hits).items()))
    result = {
        "scan": "2026-11-23 .NET 11 source first-pass boundary triage",
        "snapshot_upstream": "dotnet/dotnet v11.0.100",
        "snapshot_commit": "297acf930fb0f5c07fd4e51d78e521b4ad2e5d1f",
        "executed_target_code": False,
        "validation": "UNVERIFIED_STATIC_LEADS",
        "files_scanned": scanned,
        "roots_checked_out": present,
        "candidate_code_locations": len(hits),
        "hit_counts": counts,
        "hits": hits[:300],
    }
    OUT.joinpath("results.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    fence = chr(96) * 3
    md = ["# .NET boundary triage – 23 November 2026", "",
          "**Status: static review leads only; no vulnerabilities verified.**", "",
          "Upstream: dotnet/dotnet v11.0.100; commit 297acf930fb0f5c07fd4e51d78e521b4ad2e5d1f.",
          "", f"Files scanned: {scanned}. Candidate code locations: {len(hits)}.",
          "", "## Counts by review signal", ""]
    for k, n in counts.items():
        md.append(f"- {k}: {n}")
    md += ["", "## First 60 code locations for human validation", "",
           "A matched pattern is not evidence of exploitability; inspect the call chain and controls."]
    for h in hits[:60]:
        md.extend(["", f"### {h['pattern']} — {h['file']}:{h['line']}",
                   f"Review score: {h['review_score']}; nearby guard tokens: {', '.join(h['nearby_guard_strings']) or 'none'}",
                   fence+"csharp", h["excerpt"], fence])
    OUT.joinpath("results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"Scanned {scanned} source files in {len(present)} roots; flagged {len(hits)} code locations.")
    print("Signals:", json.dumps(counts, sort_keys=True))
    for hit in hits[:30]:
        print(f"{hit['review_score']:02} {hit['pattern']} {hit['file']}:{hit['line']} {hit['code'][:100]}")
    if scanned == 0 or len(present) != len(SCOPE):
        raise SystemExit("Missing source roots; inspect sparse checkout before relying on results")

if __name__ == "__main__":
    main()
