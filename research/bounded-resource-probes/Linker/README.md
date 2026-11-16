# Bounded ILLink source-consumer check

This is an explicitly owned build experiment. It does not prove that
a remote service accepts uploaded .NET assemblies.

The current runtime linker initializes DefaultSymbolReaderProvider(false)
and in LinkContext.RegisterAssembly calls SafeReadSymbols(assembly).
SafeReadSymbols catches errors, but they may occur after allocation.

This test builds two **identical self-generated** assemblies except
the Embedded Portable PDB declared length field:
- baseline: original (controlled) declaration;
- altered: exactly 8 MiB declared (no large actual decompression payload).

It supplies either assembly as a file reference to an independently
built Host console project, uses official .NET 10/11 SDKs and attempts
dotnet publish with PublishTrimmed enabled.

Safety and controls:
- all inputs self-created; mutation only four header bytes;
- offline Docker tests (network none) with 512 MiB memory, one CPU,
  <=75 seconds per test, <=10-minute workflow;
- only loopback and local filesystem; no external or customer service;
- records real container memory peak and elapsed time where supported;
- report package/restore failures separately from a parser failure;
- output differences are **not** evidence of remote exploitation.

If the project is not processed by ILLink or the linker is skipped, this
experiment is not a positive demonstration of the library sink.
