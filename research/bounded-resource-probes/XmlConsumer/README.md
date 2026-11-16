# Official Microsoft-authored PdbToXml converter consumer

This investigator-only harness uses the publicly published
Microsoft.DiaSymReader.Converter.Xml package 1.1.0-beta2-22164-02.
It calls the production PdbToXmlConverter.ToXml API on a genuinely
generated Portable PDB with 0/1/8 MiB embedded-source declarations.
The only input difference is the four-byte length prefix. It compares
IncludeEmbeddedSources disabled/enabled and UseNativeReader disabled/enabled
on an isolated GitHub Windows Server 2022 runner. Per-call watchdog 15s,
self-created fixture under 128 KiB, max declared 8 MiB.

A library converter is a concrete opt-in symbol tool consumer, not proof
that Visual Studio or a Microsoft service accepts externally supplied PDBs.
Process exception handling, allocation and valid controls must be evaluated
before making MSRC severity claims.
