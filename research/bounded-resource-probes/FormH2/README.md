# Bounded real Kestrel HTTP/2 form-reader check

Real h2c over 127.0.0.1 only, inside a network-disabled 384 MiB/1 CPU container.
Ten cases per supported runtime: valid 8 KiB and 32 KiB payloads, flush-sized
fragments, percent-escapes, multi-key forms, local ValueCountLimit and
ValueLengthLimit, controlled client stream reset and healthy follow-up.
Hard caps: 72 KiB request, 60s process timeout, 7s per HTTP call.
Client framing/delays confound timing; do not claim parser-specific DoS without
attributing processing work and demonstrating actual security impact.
