import json
import os
import subprocess
import time
from probe2 import health

for version in ("net10.0", "net11.0"):
    assembly = os.path.abspath(os.path.join("f043-lab", "bin", "Debug", version, "f043-lab.dll"))
    process = subprocess.Popen(["dotnet", assembly], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    result = {"version": version}
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError("server exited")
            try:
                h = health()
                if h:
                    result.update({"runtime": h["runtime"], "kestrelAssembly": h["kestrelAssembly"], "onDataCalls": h["onDataCalls"]})
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server failed to become healthy")
    except Exception as e:
        result["error"] = str(e)
    finally:
        process.terminate()
        try:
            _, err = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            _, err = process.communicate(timeout=3)
        result["stderrTail"] = err.decode(errors="replace")[-500:]
    print(json.dumps(result), flush=True)
print("F043_IL_CHECK_COMPLETE", flush=True)
