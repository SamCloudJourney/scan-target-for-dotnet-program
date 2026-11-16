# Downstream local-service tests

This project **constructs** a hypothetical local ASP.NET Core service and invokes
real library methods. It is *not* an existing Microsoft public endpoint and does
not imply default exposure.

**Input-to-consumer gates**
1. \`/symbols\`: a self-generated PE is mutated on the client, then posted over
   loopback to a deliberately symbol-reading Mono.Cecil endpoint. A
   \`readSymbols=false\` control isolates explicit symbol opt-in.
2. \`/embedded-source\`: posted compressed embedded-source bytes go to the
   actual managed Microsoft.DiaSymReader 3.0.0 extension through a stub
   document. **No native PDB parser** is exercised; this bypass must be
   recorded as a material limitation.
3. \`/form\`: real Kestrel \`Request.ReadFormAsync\` consumes a small
   application/x-www-form-urlencoded form using a chunking HttpContent.
   Oversize values test the configured limit. TCP boundaries and actual
   PipeReader wakeups are **not guaranteed** by HTTP request writes.
4. \`/health\`: establishes baseline and post-error health, including during
   three overlapping *bounded* symbol reads.

Each run executes in a container with **no external network access**, only
\`127.0.0.1\` loopback; 384 MiB total memory, one CPU, 256 MiB GC hard limit,
48 PID ceiling, read-only filesystem and 16 MiB temporary filesystem.
Maximum declared expansion 8 MiB, maximum concurrency three, maximum HTTP
body 128 KiB, total process runtime 35 s. No confidential data or external
account is accessed.

Metrics are *observed lab statistics*, **not** an attested availability
impact at a Microsoft production service. Counters based on
\`GC.GetTotalAllocatedBytes()\` are process-wide cumulative allocation and may
include unrelated work; one run per framework is not a stable latency
benchmark. Successful 200/400/422 replies do not establish a security
severity.
