#!/usr/bin/env python3
"""Create three investigator-owned, local-only NuGet symbol data fixtures."""
import hashlib
import json
import pathlib
import sys
import zipfile
if len(sys.argv) != 3:
    raise SystemExit("Usage: package_fixtures.py controlled-input-root local-feed-root")
inputs=pathlib.Path(sys.argv[1])
feed=pathlib.Path(sys.argv[2])
feed.mkdir(parents=True,exist_ok=True)
for mode in ("InputBaseline","InputSmall","InputAltered"):
    name="Research.SymbolFixture."+mode.removeprefix("Input")
    package=feed / f"{name}.1.0.0.nupkg"
    raw=(inputs/mode/"Sample.dll").read_bytes()
    if len(raw)>128*1024 or len(raw)<1024:
        raise SystemExit("Owned PE input violates size gate")
    nuspec=(f'<?xml version="1.0" encoding="utf-8"?>'
            f'<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">'
            f'<metadata><id>{name}</id><version>1.0.0</version>'
            f'<authors>OwnedSecurityLab</authors>'
            f'<description>Self-generated bounded symbol metadata fixture; no tasks.</description>'
            f'<dependencies><group targetFramework="net10.0" /></dependencies>'
            f'</metadata></package>')
    with zipfile.ZipFile(package,"w",zipfile.ZIP_DEFLATED) as out:
        out.writestr(name+".nuspec",nuspec)
        out.writestr("lib/net10.0/Sample.dll",raw)
    with zipfile.ZipFile(package) as check:
        assert check.read("lib/net10.0/Sample.dll")==raw
        entries=check.namelist()
        assert len(entries)==2
    print(json.dumps({"test":"nuget-fixture","mode":mode,
        "packageId":name,"packageBytes":package.stat().st_size,
        "assemblyBytes":len(raw),"assemblySha256":hashlib.sha256(raw).hexdigest(),
        "packageEntries":entries,"localOnly":True}))
