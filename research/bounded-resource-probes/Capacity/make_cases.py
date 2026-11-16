#!/usr/bin/env python3
"""Prepare three identical-size self-authored PE files, changing only MPDB length."""
import hashlib,json,pathlib,struct,sys
if len(sys.argv)!=3:raise SystemExit("Usage: make_cases.py Sample.dll output-directory")
original=pathlib.Path(sys.argv[1]).read_bytes()
if not (1024<len(original)<=128*1024):raise SystemExit("Invalid input size")
offset=original.find(b"MPDB")
if offset<0 or original.find(b"MPDB",offset+1)>=0 or offset+8>len(original):
    raise SystemExit("Expected exactly one embedded portable PDB header")
base=struct.unpack_from("<I",original,offset+4)[0]
if not 1<=base<=65536:raise SystemExit("Unexpected original MPDB length")
root=pathlib.Path(sys.argv[2])
for mode,declared in (("Baseline",base),("Small8MiB",8*1024*1024),("Large64MiB",64*1024*1024)):
    blob=bytearray(original)
    struct.pack_into("<I",blob,offset+4,declared)
    directory=root/mode
    directory.mkdir(parents=True,exist_ok=True)
    (directory/"Sample.dll").write_bytes(blob)
    print(json.dumps(dict(test="controlled-bounded-capacity",mode=mode,
        declared=declared,fileBytes=len(blob),
        changedByteCount=sum(a!=b for a,b in zip(original,blob)),
        sha256=hashlib.sha256(blob).hexdigest())))
