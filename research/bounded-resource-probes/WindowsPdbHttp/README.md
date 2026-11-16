# Actual Windows native-reader PDB over loopback HTTP

Tested against Microsoft.DiaSymReader 3.0.0 using the real Windows COM
symbol reader on .NET 10 and 11. Owned Kestrel HTTP service accepts an
11 KiB self-generated Portable PDB as the request body. Its 4-byte
embedded source length is modified to <=8 MiB *by the test client*,
not by the service. Input size is capped at 128 KiB.

Compare valid reads, single malformed reads, 3 concurrent malformed
requests and a guard that rejects declarations above 256 KiB before
calling the actual native-reader/managed source extraction. Health
requests run before, during and after; valid requests follow errors.
Only 127.0.0.1 is bound. Each .NET executable is killed at 45 seconds.

The server is **investigator-authored**, not a Microsoft production
service. This test proves that a hypothetical untrusted HTTP input path
can reach current Microsoft.DiaSymReader. It cannot alone establish
MSRC exploitability, a deployed trust boundary, or production DoS.
