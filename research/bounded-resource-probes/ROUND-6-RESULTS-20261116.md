# Round 6: NuGet and Windows HTTP parser reachability, bounded availability tests — 2026-11-16

**Overall finding: Two resource-amplification behaviours are now validated through genuine delivery paths, but no Microsoft production security-boundary compromise, build-worker outage, or service DoS has been demonstrated. All inputs were researcher-owned and all live HTTP traffic was bound to loopback.**

## #1 Mono.Cecil — official ILLink consumes a NuGet dependency's embedded PDB

- Daybreak ID: `csf_be39419e1b000d6304087b1a`.
- We generated three local-only packages each containing **only** an investigator-authored ~10,240-byte `Sample.dll` and `.nuspec`; no build tasks, scripts, or `.targets`. The only input-assembly difference is its embedded-PDB declared size field: valid 11,136 bytes, forged 1 MiB, forged 8 MiB.
- `dotnet restore` of each unique `PackageReference` ID succeeded, verified the exact local assembly SHA-256, then actual Microsoft.NET.ILLink.Tasks processed it during `dotnet publish -p:PublishTrimmed=true` on .NET 10 and 11. Each publication used a network-disabled Docker SDK image. A **passive** custom step inspected `LinkContext`: `Sample.HasSymbols=True`, correct NuGet-cache path/hash and declared PDB size. **6/6 publishes succeeded**.
- Cumulative managed allocation at the actual linker step:

| Runtime | Valid baseline | 1 MiB declaration | 8 MiB declaration | Difference for 8 MiB |
|---|---:|---:|---:|---:|
| .NET 10.0.15 | 370,256,032 B | 371,301,472 B | 378,646,984 B | +8,390,952 B |
| .NET 11.0.0 | 485,495,368 B | 486,508,160 B | 493,833,752 B | +8,338,384 B |

[NuGet package ingestion run 43924278807](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43924278807).

**Scope qualifier:** A build owner normally selects the dependency package. This result establishes a package-delivered data-to-parser path and extra allocations, **not** unsolicited remote access to a Microsoft service, a failed build, code execution, EoP or security-feature bypass.

## #1 bounded worker-capacity test — no availability loss

Self-generated ~10-KiB assemblies with PDB length declarations of 11,136 B, 8 MiB and **64 MiB** were processed by real ILLink in isolated containers. Two runs per input, per runtime (12 total). RAM limits were **560 MiB (.NET 10)** and **640 MiB (.NET 11)**, no external network, 2 CPUs and strict timeouts.

| Runtime | Baseline mean cumulative GC allocation | 64 MiB input mean | Added managed allocation | Build outcome |
|---|---:|---:|---:|---|
| .NET 10.0.15 | 370,251,932 B | 437,354,820 B | +67,102,888 B | 6/6 successful; 0 OOM kills |
| .NET 11.0.0 | 485,490,756 B | 552,569,520 B | +67,078,764 B | 6/6 successful; 0 OOM kills |

Actual input path, hash and PDB length were confirmed inside `LinkContext`. Cgroup peak RAM fluctuated and did not scale monotonically with declared length. **No worker outage**, even under the imposed test budgets.

[Corrected capacity run 43927178642](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43927178642).

**Invalid setup excluded:** [Initial capacity run 43925735181](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43925735181) failed on **every baseline and modified** input before publishing because a network-disabled restore could not retrieve `Microsoft.NETCore.App.Runtime.linux-x64` and `Microsoft.AspNetCore.App.Runtime.linux-x64` (NU1101). Docker OOMKilled=false. Do **not** count those failures as exploit evidence.

## #2 DiaSymReader 3.0.0 — real HTTP-uploaded PDB to Windows native reader

- Daybreak ID: `csf_45f67970764773b396ffbc58`.
- A **researcher-authored** localhost-only ASP.NET Core server accepted an actual **11,636-byte Portable PDB** in the request body and passed it through real Windows `SymUnmanagedReaderFactory` to `GetEmbeddedSource`. The loaded native reader module was `Microsoft.DiaSymReader.Native.amd64.dll`. Oversized allocation is in the **managed** extraction extension, not proven native corruption.
- Valid input extracted **7,217 source bytes**, HTTP 200. Forged 8 MiB declared-source field returned HTTP 422 / `InvalidDataException` after managed allocation. A researcher-added 256-KiB declared-source cap rejected early without reaching the large allocation:

| Observation | .NET 10.0.15 | .NET 11.0.0 |
|---|---:|---:|
| One forged PDB, unguarded cumulative managed allocation | 8,466,968 B | 8,456,608 B |
| One forged PDB, investigator guard | 46,040 B | 42,016 B |
| Three parallel forged uploads, combined process allocation | 25,418,904 B | 25,478,352 B |
| Health during/after, valid PDB after | HTTP 200 | HTTP 200 |

Per-request cumulative counts can overlap when processing is concurrent; the 3-request figures are whole-operation aggregate allocation values.

[Windows COM reader real HTTP test 43924788375](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43924788375).

**Scope qualifier:** This is an **investigator-created HTTP consumer**, not a Microsoft deployed service. The parser rejects malformed input and the test service remains healthy. A supported Microsoft application that automatically handles lower-trust PDB embedded-source extraction, and an actual availability failure, remain **unproven**.

## #3 FormPipeReader

The historical issue is already disclosed and fixed as **CVE-2026-70196**. Previous Round 5 testing on patched .NET 10.0.15 and 11.0.0 showed normal HTTP/1.1 and HTTP/2 parsing and successful recovery. No new root cause or supported-version denial of service was demonstrated. No additional #3 experiments were warranted in Round 6.

## Microsoft Security Response Center assessment

- **Technical root-cause confidence:** High for #1 and #2.
- **Importance/severity:** Neither reaches a demonstrated Important-level security impact; #3 is known and fixed.
- **What is still missing:** An affected, supported, **in-scope Microsoft product or service** that processes lower-trust input and suffers reproducible availability loss, with suitable controls. Artificial memory caps and our own HTTP service do not supply that proof.
- Cumulative managed allocation is **not** RSS, peak committed memory, OOM, or a security compromise.
- The .NET bounty program requires **Critical or Important** severity with direct and demonstrable security impact: https://www.microsoft.com/en-us/msrc/bounty-dot-net-core .
- Source is on a **public research branch**. Microsoft's coordinated disclosure policy recommends private security submissions: https://github.com/dotnet/runtime/security/ . Consider disclosure requirements before sharing additional exploit-oriented information.

For complete machine-readable data, raw GitHub Actions artifacts and controls, see the accompanying Round 6 ZIP delivered in the research conversation.
