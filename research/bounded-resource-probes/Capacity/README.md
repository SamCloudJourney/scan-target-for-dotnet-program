# ILLink worker capacity experiment (explicitly NOT production DoS)

An investigator-generated PE contains a controlled embedded Portable PDB
size field of 11 KiB, 8 MiB, or 64 MiB, changed by four bytes at most.
The official .NET 10.0.15 and .NET 11.0.0 ILLink task runs on clean
projects, with a passive custom step verifying the actual assembly
path, hash, PDB declaration, and GC allocation after symbol reading.

Each case repeats twice, alternating order, in individual networkless
Docker containers. Artificial memory budgets are 560 MiB (.NET 10)
and 640 MiB (.NET 11). Docker OOM state, build exit and cgroup peak
are recorded with one-worker and 80s timeout limits.

An OOM under these imposed caps would prove only that a deliberately
resource-limited worker is sensitive to a crafted input. It would NOT
by itself demonstrate a Microsoft remote service outage or Important
MSRC severity, especially where a consumer explicitly trusts packages
or input assemblies.
