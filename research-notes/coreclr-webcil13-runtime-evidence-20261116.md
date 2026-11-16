# CoreCLR #13 — WebCIL pre-validation relocation, real-runtime evidence

**Date:** 2026-11-16  
**Scope:** Owned public GitHub Actions runner, .NET 11.0.0 CoreCLR `browser-wasm` hosted under Node.  
**Disposition:** Confirmed reproducible *abrupt runtime termination* on a specific malformed WebCIL input. No demonstrated native-host RCE, browser escape, or arbitrary memory write.

## Source evidence

- `scan-target-v11.0.100/src/runtime/src/coreclr/vm/peimagelayout.cpp`: `InitDecoders` initializes the WebCIL decoder and invokes `ApplyBaseRelocations(true)` when relocations are advertised, before the later `CheckILFormat` call in the stream-loading path.
- `scan-target-v11.0.100/src/runtime/src/coreclr/utilcode/webcildecoder.cpp`: relocation-section header-derived raw offset and length flow to the relocation routine without a full image-bounds check at that retrieval point.
- `scan-target-v11.0.100/src/runtime/src/coreclr/vm/assemblynative.cpp`: `AssemblyNative_LoadFromStream` calls `PEImage::CreateFromByteArray` before `CheckILFormat()`.
- The same relevant ordering was also observed in the upstream `dotnet/runtime` main-branch source at the time of review.

## Dynamic evidence

**Workflow:** [Five-run relocation differential](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43924129676).  
**Follow-up diagnostic:** [Runtime exit-stack and passive heap-view test](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43924663111).  
**Prior source and isolated sanitizer model:** [Source/model validation](https://github.com/SamCloudJourney/scan-target-for-dotnet-program/actions/runs/43916533245).

A native CoreCLR `browser-wasm` application was built with `UseMonoRuntime=false`; it printed `.NET 11.0.0` and `Browser` at runtime.

| Independent process | Input class | Observed behavior |
| --- | --- | --- |
| Control | Ordinary malformed/truncated assembly | `BadImageFormatException` |
| Control | Malformed WebCIL with relocation disabled | `BadImageFormatException` |
| Control | Invalid relocation-section index | `BadImageFormatException` |
| Control | Too-short relocation directory | `BadImageFormatException` |
| Control | Relocation target inside a 256-byte image | `BadImageFormatException` |
| Probe 1–5 | Same controlled malformed image with relocation target far outside image | Abrupt host exit code `1`, 5/5 attempts |

A JavaScript diagnostic intercepted `process.exit(1)` invoked by the `.NET` WebAssembly host during `runMain`. In the OOB case, the managed code printed its marker immediately before `Assembly.Load` but did not reach a managed exception return. That is materially different from the negative controls.

**Caution:** The trace does **not** identify a particular faulting WebAssembly memory instruction and is not equivalent to a source-level sanitizer finding in the production binary. The likely memory bounds failure is consistent with the source, but must be established by instrumenting the runtime itself.

The passive post-return heap view for an in-range control was accessible, but no retained matching WebCIL image allocation was found. Thus that experiment gives **no proof of a retained mutated allocation** and does not disprove the source finding.

## Current conclusion and gaps

- **Reproduced:** abnormal CoreCLR WebAssembly process termination correlated with relocation targeting outside a malformed input image.
- **Not reproduced:** arbitrary memory corruption affecting an attacker-selected object, code execution, host escape, remote entry point, or unauthorized access.
- **Threat-model dependency:** untrusted actor must control the image that a consumer passes to the CoreCLR loader; code loading in ordinary managed applications is not by itself a new security boundary.
- **Defensible current classification:** availability failure / memory-safety candidate, not confirmed RCE. Microsoft/MSRC severity remains an independent decision.

## Appropriate follow-up

The strongest next step is a non-public, instrumented CoreCLR build recording the validated input size, full relocation-directory and block ranges, target offset, target write width, and the exception/trap location. A concrete lower-trust load path and affected service boundary would be necessary before assigning remote impact.

This note intentionally avoids describing a functional code-execution chain or asserting unobserved impact.
