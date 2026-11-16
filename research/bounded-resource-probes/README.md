# Bounded .NET resource probes — independent lab

This branch contains **controlled experiments**, not a claim of a Microsoft vulnerability.
No requests leave the GitHub-hosted runner, and no third-party service is probed.

- \`form\`: invokes the **actual** framework-shipped FormPipeReader through a synthetic incremental PipeReader. It does not demonstrate real-world HTTP streaming behavior. Maximum body 524,288 bytes, step 1–256 bytes.
- \`cecil\`: patches only the declared Embedded Portable PDB length of an assembly produced on the runner, then uses Mono.Cecil **NuGet 0.11.6** with ReadSymbols enabled. This package is a version-analogue; its identity is not proof of the VMR source build.
- \`cecil-model\`: isolated sink replica of VMR source; declared allocation <= 8 MiB.
- \`diasym-model\`: isolated managed sink replica; declared allocation <= 8 MiB. It does **not** instantiate a native Windows DiaSymReader consumer.

Run controls: 8-second cancellation token for the form parser, an external 12-second timeout per probe, 8-minute maximum GitHub Actions job, and 8 MiB maximum synthetic declared allocations. Results are JSONL with measured time, CPU and allocated bytes. Failures, exceptions and tool versions must be retained. The whole source repository is not built or executed.

Source snapshots inspected: .NET 10.0.15 and .NET 11.0.0. A public advisory, CVE-2026-70196 (October 13, 2026), already describes incremental FormPipeReader rescanning and labels 10.0.13 as patched. Do not submit a duplicate without establishing a new unpatched condition in released binaries.

Keep full independent validation and any coordinated disclosure private.
