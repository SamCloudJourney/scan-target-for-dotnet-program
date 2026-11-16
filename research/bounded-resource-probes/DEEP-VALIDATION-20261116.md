# Downstream resource validation — 16 November 2026

All tests executed on investigator-created local inputs and isolated GitHub runners. No public endpoints were probed. The branch contains runnable harnesses and workflows.

| ID | GitHub Actions run | Downstream result |
|---|---|---|
| csf_be39419e1b000d6304087b1a | https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43818699725 | Actual Mono.Cecil parser accepted an 18,494-byte PE that inflated to 1,059,712 bytes while declaring only 1 byte. Measured 4,116,456 managed allocation bytes on .NET 10.0.15. An 8 MiB declaration caused 8,444,360 allocation bytes; disabling symbol reading reduced it to 16,480 bytes. Supported .NET 11.0.0 behaved similarly. |
| csf_45f67970764773b396ffbc58 | https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43818150420 | Real 11,688-byte Portable PDB was accepted by managed PortablePdb 1.6.0 and DiaSymReader 2.2.15; 8 MiB forged EmbeddedSource length led to 8,442,016 allocated bytes before InvalidDataException. Native Windows reader and production consumer not tested. |
| csf_2afdb97d9893b9041f099aff | https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43817482871 | Actual local Kestrel ASP.NET Core 10.0.15 and 11.0.0 accepted 64 KiB URL-encoded value, rejected over-limit 66 KiB value with HTTP 400, and remained responsive. The historical repeated-scan flaw is known CVE-2026-70196, patched in 10.0.13. |

## Attacker-controlled input and security boundary

- **Mono.Cecil:** Malicious PE/PDB debug metadata causes memory amplification when an explicitly configured service/tool reads symbols. A single local test or allocation counter does not establish practical outage, authentication bypass, EoP or RCE. A real affected Microsoft consumer accepting untrusted assemblies remains unidentified.
- **DiaSymReader:** A small, valid-layout Portable PDB can make a managed source reader allocate the record's declared size before rejecting malformed content. Any deployment impact requires a PDB ingestion workflow that invokes embedded-source extraction. Real native Windows reader reachability is not established.
- **FormPipeReader:** The publicly disclosed historical algorithmic-complexity attack can affect out-of-date deployments. It is not a new unfixed vulnerability on the tested supported releases.

## Resource and reproducibility limits

384 MiB memory ceiling per Linux container, 1 CPU, 256 MiB GC limit, 48 PID limit, no outside network access, loopback-only local HTTP, 12–35 second per-process timeouts, maximum 8 MiB declared size, maximum 1 MiB appended inflation, and at most 3 parallel requests.

Package provenance: Mono.Cecil NuGet 0.11.6; DiaSymReader 3.0.0 (synthetic document) and 2.2.15 plus PortablePdb 1.6.0 (real PDB). Managed allocated bytes are not peak RSS and cannot prove worker termination.

## Research decision

Finding #1: real parser-level allocation and unbounded output behavior, not proven remotely exploitable. Finding #2: real managed Portable PDB input accepted and preallocation confirmed, but no service-level availability failure. Finding #3: known and patched. None is ready for a new Important/Critical MSRC report without additional concrete consumer impact.
