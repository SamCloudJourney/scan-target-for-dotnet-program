# Resource exhaustion: third independent bounded validation round (2026-11-16)

This report corrects earlier speculative availability conclusions. **No production Microsoft service was tested or demonstrated to go down.** Source and measurement evidence are in the linked GitHub Actions runs.

## Outcomes

| Finding | Real downstream experiment | Observed result | Current disposition |
|---|---|---|---|
| `csf_be39419e1b000d6304087b1a` | Actual Mono.Cecil symbol reader; actual .NET 10/11 ILLink trimmed publishing | Direct parser allocates from forged PDB size and accepts output larger than declared. Twelve balanced official SDK publishing trials all succeeded; container-wide peak RAM did **not** scale monotonically with the declaration. | Source-to-parser proven; production denial of service unproven |
| `csf_45f67970764773b396ffbc58` | Actual Portable PDB through Windows COM DiaSymReader reader and managed `GetEmbeddedSource` | Approximately 11.6 KiB PDB with forged 8 MiB source length drives about 8.45 MB of managed allocation before `InvalidDataException`; `Microsoft.DiaSymReader.Native.amd64.dll` is loaded. | Genuine reader-to-allocation path proven; debugger/service outage unproven |
| `csf_2afdb97d9893b9041f099aff` | Actual Kestrel form reader on .NET 10.0.15/11.0.0, historical 10.0.12 positive control | Patched supported binaries use `scannedLength`; controlled form limits work and health endpoint remains responsive. | Known CVE-2026-70196, patched in .NET 10.0.13 |

### Guarded controls

- Mono.Cecil 8 MiB declared PDB: real parser **8,444,328** measured managed allocation bytes on .NET 10.0.15; investigator's 256 KiB prevalidation **8,200** bytes, rejecting the input. `ReadSymbols=false` is an additional control. Valid symbol data still passes the prevalidation.
- DiaSymReader real Portable PDB 8 MiB declaration on .NET 10.0.15: **8,442,024** allocated bytes before the normal exception; investigator guard: **0** measured bytes after entering the guarded processing interval, rejecting early. A Windows COM-reader test confirmed **8,458,464** bytes on .NET 10.0.15 and **8,447,208** bytes on .NET 11.0.0.
- The deliberately configured local ASP.NET Core service accepted valid guarded inputs, returned controlled error responses to oversize records and stayed available for its health checks.

### Official SDK ILLink A/B attribution check

First successful run: [43823144891](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43823144891). Balanced 12-case run: [43823556873](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43823556873). All 12 publishes exited successfully. Measured whole-container peaks (MB):

| SDK | Baseline | Declared 1 MiB | Declared 8 MiB |
|---|---|---|---|
| .NET 10 | 530.0, 533.0 | 526.3, 516.4 | 538.4, 539.0 |
| .NET 11 | 591.4, 622.3 | 593.4, 647.0 | 597.9, 605.1 |

There is no stable, monotonic trend. The first restricted A/B [43822611342](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822611342) failed for both baseline and modified assemblies due a task-host/environment constraint; **not a vulnerability**. Results from that failed baseline are not used as exploit evidence.

## Exact evidence

- [Bounded Mono.Cecil decompression and size-budget test](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43821406313)
- [Actual Portable PDB managed-reader budget test](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43821406176)
- [Localhost ASP.NET Core endpoint, guarded and unguarded](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43821701110)
- [Windows COM reader on supported .NET 10/11 runtimes](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43822132014)
- [Repeated official .NET ILLink builds](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43823556873)

## Scope and impact

A malicious assembly/PDB may increase memory allocation for a **configured consumer which accepts and parses that untrusted artifact**. These tests do not show account takeover, privilege elevation, remote code execution, native memory corruption, outage of another tenant, or exploitable remote availability loss on a Microsoft-deployed service. The apparent Windows native reader reachability uses a managed extension for the allocation; it is **not** the unrelated native-PDB heap overwrite disclosed as CVE-2026-118745.

The Microsoft .NET bounty requires demonstrable Critical/Important impact in scope. Neither #1 nor #2 has crossed that bar; #3 is known/fixed. Keep any future sensitive deployment proof private for coordinated MSRC reporting.

## Limits

Self-generated PE/PDB only, max 8 MiB declared lengths, <=1 MiB added actual decompression, 256 KiB investigator guard, network-disabled isolated containers, bounded 384/768 MiB container memory, 1/2 CPUs and per-command timeouts, <=3 concurrent loopback service requests. Windows tests used 15-second individual process timeouts and tiny source fixtures. Managed allocation counters are **not** resident peak memory; container peak includes unrelated build work.
