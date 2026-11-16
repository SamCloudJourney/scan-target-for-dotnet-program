# Local NuGet package input to official Microsoft ILLink

This validates the real NuGet PackageReference delivery path for an owned
.NET assembly whose embedded-PDB declared size is the only mutated field.
Three distinct local-only packages prevent cache-identity contamination:
baseline, 1 MiB and 8 MiB. No package has build scripts, targets, or tasks.

The official linker passive extension records actual package assembly path,
hash, PDB declaration, symbol-read state and cumulative managed allocations.
NuGet restore reads a local test feed and public dependencies; publish runs
offline in containers with 768 MiB RAM, 2 CPUs, 128 PIDs, 100s per case.

This is not proof of automatic ingestion by a Microsoft remote service or
a high/low trust boundary: project authors ordinarily select dependencies.
No package is uploaded to a public registry. All binary inputs are generated
locally and remain under 128 KiB.
