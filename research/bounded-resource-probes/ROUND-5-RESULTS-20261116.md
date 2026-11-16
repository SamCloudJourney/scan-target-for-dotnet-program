# Round 5 — deeper bounded resource/availability validation (16 November 2026)

**Overall outcome:** Concrete product and tool ingestion was demonstrated for two parser findings, but **no supported Microsoft product crash, cross-tenant interruption, remote availability impact, code execution, EoP, or new patched-runtime form DoS** was demonstrated. All inputs were self-generated and tests were bounded.

## Finding #1 — Mono.Cecil: real official ILLink ingestion and cumulative allocations

Finding ID: `csf_be39419e1b000d6304087b1a`.

**Validated actual ILLink path:** Fresh, independent publish directories prevent previously created `Sample.dll` outputs from being selected accidentally. Custom `IStep` instrumentation inside the **official** Microsoft.NET.ILLink.Tasks 10.0.15 and 11.0.0 linker reports:
- `Sample.HasSymbols=True` for every normal and modified assembly;
- linker input path under `/fixtures/InputBaseline`, `/fixtures/InputSmall`, `/fixtures/InputAltered`, with exact SHA-256 prefix matching the supplied input;
- parsed PDB size declaration 11,136 bytes (valid), 1,048,576 bytes, and 8,388,608 bytes;
- two balanced repetitions per size per runtime; all **12/12 publishes succeeded**.

**Cumulative .NET GC bytes at the real linker custom-step boundary** (each cell = mean of two runs). These are post-ingestion process totals, **not direct individual call-site allocations or resident memory**.

| Runtime | Valid baseline | 1 MiB declaration | 8 MiB declaration | 8 MiB vs baseline |
|---|---:|---:|---:|---:|
| .NET 10.0.15 | 370,253,664 | 371,291,024 | 378,637,512 | **+8,383,848** |
| .NET 11.0.0 | 485,488,820 | 486,515,240 | 493,852,556 | **+8,363,736** |

The near-1:1 size-dependent increase with otherwise matching test inputs is evidence of real linker allocation amplification. GC heap and working set were not monotonic, and no user-visible failure was observed.

- [Official ILLink 12-case instrumented run](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43916778900)
- [Correct input path and hash verification, 4 cases](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915936996)
- [Earlier misleading test with stale output resolution](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43914389117): formally superseded; **do not cite as proof that modified input was parsed**.

**Impact/limit:** A producer able to supply assemblies to a symbol-reading linker can cause unnecessary managed allocations from forged embedded-PDB size metadata. The demonstrated work happens in a real Microsoft build tool. Remote or lower-trust production ingestion, developer-to-server privilege boundary, failed publish, prolonged worker unavailability, RCE or EoP are **not** proved.

## Finding #2 — DiaSymReader: current package plus real converter

Finding ID: `csf_45f67970764773b396ffbc58`.

The same small, self-generated Portable PDB reached a real Windows COM symbol reader and managed embedded-source extraction. Comparing **Microsoft.DiaSymReader 2.2.15 versus 3.0.0**, `declared=8,388,608` allocated **8,450,528 cumulative managed bytes per request in each version**, and threw `InvalidDataException`; unchanged source extracted. The loaded native module was `Microsoft.DiaSymReader.Native.amd64.dll`. Allocation is from managed extraction, not proof of a native memory overwrite.

- [Windows version differential](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915536549)

For a **concrete Microsoft-authored downstream consumer**, a harness called `PdbToXmlConverter.ToXml` from historical published `Microsoft.DiaSymReader.Converter.Xml` version `1.1.0-beta2-22164-02` (via Microsoft's public dnceng tools feed). Same 11,632-byte PDB, with only its embedded-source size field altered:

| Converter mode | Declared 8 MiB case | Outcome |
|---|---:|---|
| `IncludeEmbeddedSources=false` | 96,416 managed allocated bytes | Successfully converted |
| `IncludeEmbeddedSources=true`, managed reader | 8,485,448 bytes | InvalidDataException |
| `IncludeEmbeddedSources=true`, native reader | 8,448,304 bytes | InvalidDataException |

The valid source converted in both reader modes. Optional embedded-source extraction is a **required gate**. The historical converter package is not by itself evidence of a currently in-scope product vulnerability.

- [Real PdbToXml converter API ingestion](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43916639270)

**Same-process availability check:** After three malformed conversions with source extraction enabled, **all three subsequent benign conversions succeeded in that same process**, both with the managed and native reader (6/6 healthy recoveries). There was no process termination or durable conversion failure.

- [Actual PdbToXml bounded recovery](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43917600049)
- [Previous Microsoft vsdbg DAP source request negative control](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43865155310): source retrieval not reached; not evidence of an affected debugger.
- [Previous open-source debugger DAP control](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43866661982): source request unsupported for benign and altered PDB.

**Impact/limit:** Exact source extraction in a real tool triggers an avoidable bounded allocation before exception. A currently supported Microsoft debugger/source service accepting a lower-trust PDB, with meaningful unavailability, is still not established. **No demonstrated MSRC Important DoS**.

## Finding #3 — patched FormPipeReader: actual HTTP/1.1 and HTTP/2

Finding ID: `csf_2afdb97d9893b9041f099aff`. Original quadratic scan issue is publicly disclosed as **CVE-2026-70196** and patched from ASP.NET Core 10.0.13. No new root cause yet.

- [Actual Kestrel HTTP/1.1 segmented uploads, limits and cancellation](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43864934044).
- [Actual loopback Kestrel HTTP/2, ten controlled cases per runtime](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43915151665).
- [HTTP/2 follow-up concurrent streams and same-connection identity](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43917203189).

On .NET 10.0.15 and 11.0.0, valid form bodies parsed, configured overcount and value caps returned HTTP 400, client stream resets were contained, and healthy requests remained HTTP 200. Kestrel connection identifiers matched across **before/after reset, two concurrent health probes, and the next valid form request**. Tests used a real HTTP/2 connection; timing includes deliberate client frame pacing, so it cannot be attributed solely to parser cost.

**Disposition:** Negative on current supported releases; known already-fixed CVE, not a new bounty candidate on available evidence.

## Evidence method and limits

- No real/public target or user data was tested: all live traffic was **owned loopback** on GitHub-hosted runners.
- Inputs were investigator-generated PE/PDB, typically 4–12 KiB, declarations up to 8 MiB; no megabyte/gigabyte payload-flooding.
- Linux tests used network-disabled Docker, 384–768 MiB memory and 1–2 CPUs, process timeout and GC budgets. Windows reader operations had a 15-second watchdog; only three repeated extractions per reader mode.
- `GC.GetTotalAllocatedBytes` measures **cumulative allocation**, not working set, committed memory, or OOM.
- Normal source conversion after malformed PDB extraction and the normal HTTP/2 connection after stream reset both worked.
- GitHub branch is **public**. Do not assume the publication of potentially undisclosed vulnerability details is compatible with every program's coordinated-disclosure requirements; evaluate that before further public exploit publication.

## MSRC evidence decision

| Candidate | Highest demonstrated effect | MSRC Important/Critical evidence today |
|---|---|---|
| #1 Mono.Cecil | Deterministic 8+ MiB extra cumulative allocation in genuine .NET 10/11 ILLink process, no failed build | **Not established** |
| #2 DiaSymReader | Direct Windows reader and Microsoft PdbToXml conversion resource amplification, clean recovery | **Not established** |
| #3 FormPipeReader | Regressions not reproduced on patched versions, old issue fixed | **No new candidate** |

Next material proof for #1 or #2 is a supported, in-scope lower-trust Microsoft consumer where the malformed input produces reproducible availability degradation relative to a clean control. Do **not** treat an arbitrary artificial memory cap or increase in a declared field as severity proof.
