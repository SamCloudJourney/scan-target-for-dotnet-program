# Resource exhaustion: Round 4 bounded validation (16 November 2026)

**Disposition:** No currently supported .NET remote DoS, service crash, RCE, EoP, or cross-user impact demonstrated. All experiments are local and isolated, with source-backed controls. Record both positive and falsifying results.

## 1. Mono.Cecil (csf_be39419e1b000d6304087b1a)

### Actual reader selection, direct versus ILLink-style code

[Completed GitHub run 43825379450](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825379450).

The test uses a locally generated embedded-PDB PE, with **only** the 4-byte declared size changed, and calls the same DefaultSymbolReaderProvider(false) / ModuleDefinition.ReadSymbols pattern as `dotnet/runtime/src/tools/illink/src/linker/Linker/LinkContext.cs`. The test is a minimal reproduction of a real consumer's **selection path**, not an instrumented ILLink build.

| .NET 10.0.15 input | ReadSymbols=false allocation | ILLink-style allocation | Result |
|---|---:|---:|---|
| 1 MiB declaration | 16,400 B | 1,224,376 B | Symbols loaded |
| 8 MiB declaration | 16,400 B | 8,562,896 B | Symbols loaded |
| -1 declaration | 16,400 B | 24,600 B | Caught ArgumentOutOfRangeException |

Same pattern on .NET 11.0.0. The ILLink-style provider selected `Mono.Cecil.Cil.EmbeddedPortablePdbReader` for the valid positive declarations.

### Framework alternative negative control

[Completed GitHub run 43826008167](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826008167).

The same forged 8 MiB PE passed Mono.Cecil's symbol reader and allocated roughly 8.56 MB. By contrast, the framework `System.Reflection.Metadata.PEReader.ReadEmbeddedPortablePdbDebugDirectoryData` rejected it with `BadImageFormatException`, allocating approximately 14 KB. **Do not generalise this finding to all .NET symbol readers.**

### Production consumer test and limitation

Official .NET 10/11 trimmed publishing successfully processed the controlled altered assembly on both runtimes. The balanced 12-trial run [43823556873](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43823556873) found **no consistent or monotonic container peak-memory relationship** with the forged PDB declaration. All 12 publishes returned success. The actual ILLink build has not been instrumented to prove precisely how often the observed reader is invoked in the published pipeline.

**What an attacker could conditionally do:** supply a modified assembly to a configured consumer that reads untrusted embedded symbols, forcing bounded but disproportionate allocation/decompression. In-scope low-trust production ingestion, worker failure and meaningful availability loss **remain unproven**.

## 2. DiaSymReader (csf_45f67970764773b396ffbc58)

### Real Windows COM reader and repeated recovery

[Completed GitHub run 43825476849](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825476849).

The Windows runner used a real locally generated Portable PDB, `SymUnmanagedReaderFactory` COM reader, a loaded `Microsoft.DiaSymReader.Native.amd64.dll`, real document enumeration and the managed `GetEmbeddedSource` extension. Each of three malformed extractions with an 8 MiB source declaration allocated approximately 8.43–8.45 MB before `InvalidDataException`. Immediately after each rejection a **valid, unchanged PDB extraction in the same process succeeded**. This reproduced on .NET 10.0.15 and 11.0.0.

| Observation | Result |
|---|---|
| Malformed requests (per framework) | 3 of 3 rejected with managed InvalidDataException |
| Healthy extraction after every failure | 3 of 3 succeeded |
| Process unavailable or terminated | No |
| Demonstrated long-lived resource leak | No |

An actual developer-tool consumer exists in the public `dotnet/symreader-converter` codebase: `PdbToXmlConverter.WriteEmbeddedSource` calls `doc.GetEmbeddedSource()` **only when `PdbToXmlOptions.IncludeEmbeddedSources` is enabled**. This is **source-only reachability**, not a dynamic reproduction or confirmation of Microsoft .NET bounty eligibility. [Source](https://github.com/dotnet/symreader-converter/blob/main/src/Microsoft.DiaSymReader.Converter.Xml/PdbToXml.cs).

**What an attacker could conditionally do:** trigger managed allocation pressure when an application explicitly extracts embedded source from supplied PDB files. Under tested conditions, exceptions were contained and healthy work continued. No crashing debugger or remote-service DoS demonstrated.

## 3. FormPipeReader (csf_2afdb97d9893b9041f099aff)

### Corrected multi-segment and byte-encoding matrix

[Completed segmented UTF-8/UTF-16 matrix 43825912413](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43825912413). All 78 cases produced expected results, including UTF-16LE and UTF-16BE with delimiter bytes split across incremental reads.

A first version of the reader used repeated ReadOnlySequence.GetPosition; it was corrected to use **precomputed SequencePosition** values before interpreting timing. Despite the correction, a small-segment cost remained.

### Traversal attribution

[Completed segment-size and advance-only control 43826494486](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826494486). For supported .NET 10.0.15, 8 KiB UTF-8 and one-byte increments:

| Segment size | FormPipeReader | Same inputs with SequenceReader.Advance only | Reader-only |
|---|---:|---:|---:|
| 13 bytes | 168.1 ms | 150.1 ms | 4.6 ms |
| 64 bytes | 49.8 ms | 44.5 ms | 5.3 ms |
| 512 bytes | 19.2 ms | 11.5 ms | 4.8 ms |
| 4096 bytes | 13.9 ms | 7.0 ms | 4.7 ms |

.NET 11 exhibited a similar trend. Source inspection identifies the cost: the patched multi-segment parser resumes by instantiating a new SequenceReader and calling `sequenceReader.Advance(resumeSkipped)` for each read, traversing prior segment boundaries. **This is not a full-byte delimiter rescan.**

### Actual System.IO.Pipelines default

[Completed real-pipe geometry run 43826651389](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43826651389).

For 8 KiB UTF-8 written one byte at a time, a normal in-memory Pipe retained **at most three segments**, not 630+ artificial 13-byte segments. The real FormPipeReader returned correct values and was invoked only 34 times on .NET 10.0.15 and 33 on .NET 11.0.0, despite thousands of tiny writes. Elapsed times were 14.5 ms and 12.7 ms respectively. The test uses System.IO.Pipelines, **not** a networked Kestrel endpoint; normal network buffering may differ.

The original full-byte quadratic rescan is already publicly disclosed as [CVE-2026-70196](https://github.com/dotnet/announcements/issues/465), patched beginning in ASP.NET Core 10.0.13. No supported-version network DoS was reproduced here.

## Reproducibility and safety

- Source branch: `research/bounded-resource-probes-20261116`, with test projects `LinkerLike/`, `WindowsGate/`, `FormMatrix/`, `PipeShape/`.
- All payloads are self-generated. No public services, external victim data or privileged credentials used.
- Linux test containers: 384 MiB RAM, 1 CPU, no network, read-only with small tmpfs; per-case external timeouts.
- Windows native COM tests: a self-generated 11–12 KiB PDB, 8 MiB max declared length, only 3 repeat extractions, each with a benign control and 15-second process watchdog.
- All allocation numbers are **managed cumulative allocations**, not committed peak memory or proof of process termination.
- Toolchain and libraries are pinned inside each C# project and workflow. Read original GitHub Action logs for exact versions and exceptions.

## MSRC readiness

| Finding | Confidence in parser behaviour | Confirmed production impact | New MSRC vulnerability ready? |
|---|---|---|---|
| #1 Mono.Cecil | High | None | No |
| #2 DiaSymReader | High | None | No |
| #3 FormPipeReader | High in segmented synthetic model; low for attacker control over default buffering | None | No; known patched CVE |

**Research decision:** Investigate one real, currently supported, lower-trust Microsoft file ingestion or symbol-extraction consumer **before** increasing payload sizes. Broader memory stress without that boundary will not substantiate an Important/Critical vulnerability.
