# Same reader source, version comparison

Build the exact same Windows COM symbol-reader harness against official
Microsoft.DiaSymReader NuGet versions 2.2.15 and 3.0.0 under .NET 11.0.0.
Only a locally generated Portable PDB is consumed. Its 4-byte embedded
source declaration varies between original, 1 MiB, and 8 MiB. Limit each
operation to 15 seconds. Observe exception containment, managed allocation,
native module loading and positive unmodified controls.

No third-party targets or arbitrary PDB uploads. This is not a claim of
native memory corruption or a remote service denial of service.
