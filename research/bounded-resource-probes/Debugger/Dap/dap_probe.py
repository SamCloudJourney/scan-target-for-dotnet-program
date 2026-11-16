"""Bounded Debug Adapter Protocol client for only self-generated local C# fixtures."""
import argparse
import json
import os
import queue
import subprocess
import threading
import time

p = argparse.ArgumentParser()
p.add_argument("--adapter", required=True)
p.add_argument("--program", required=True)
p.add_argument("--source", required=True)
p.add_argument("--case", required=True)
p.add_argument("--output", required=True)
args=p.parse_args()

q=queue.Queue()
log=[]
seq=0
start=time.monotonic()
proc=subprocess.Popen([args.adapter,"--interpreter=vscode"],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
    creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0),bufsize=0)

def collect():
    try:
        while True:
            header=b""
            while b"\r\n\r\n" not in header:
                one=proc.stdout.read(1)
                if not one: return
                header+=one
                if len(header)>8192:return
            size=0
            for line in header.decode("ascii","replace").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    size=int(line.split(":",1)[1].strip())
            if size<1 or size>2_000_000:return
            payload=b""
            while len(payload)<size:
                part=proc.stdout.read(size-len(payload))
                if not part:return
                payload+=part
            try: q.put(json.loads(payload))
            except ValueError: pass
    except Exception as e:
        q.put({"type":"exception","message":str(e)})
threading.Thread(target=collect,daemon=True).start()

def send(command,arguments):
    global seq
    seq+=1
    data=json.dumps({"seq":seq,"type":"request","command":command,"arguments":arguments}).encode()
    proc.stdin.write(b"Content-Length: "+str(len(data)).encode()+b"\r\n\r\n"+data)
    proc.stdin.flush()
    return seq

def await_obj(test,seconds=10):
    for a in log:
        if test(a): return a
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try: obj=q.get(timeout=max(.05,min(.5,deadline-time.monotonic())))
        except queue.Empty:continue
        log.append(obj)
        if test(obj):return obj
    return {"type":"timeout"}

def reply(request_seq,seconds=10):
    return await_obj(lambda a:a.get("type")=="response" and a.get("request_seq")==request_seq,seconds)

def event(name,seconds=10):
    return await_obj(lambda a:a.get("type")=="event" and a.get("event")==name,seconds)

report={"test":"real-vsdbg-dap-debugger-source",
        "case":args.case,"program":os.path.basename(args.program)}
try:
    r=reply(send("initialize",{"adapterID":"coreclr","clientID":"research-fixture",
        "linesStartAt1":True,"columnsStartAt1":True,"pathFormat":"path",
        "supportsRunInTerminalRequest":False,"supportsVariableType":True}),12)
    report["initializeOk"]=r.get("success",False)
    if not report["initializeOk"]:
        report["initializeMessage"]=r.get("message","");raise RuntimeError("DAP initialize not successful")
    launch_seq=send("launch",{"name":"ResearchFixture","type":"coreclr","request":"launch",
        "program":args.program,"cwd":os.path.dirname(args.program),"stopAtEntry":True,
        "justMyCode":False,"console":"internalConsole","requireExactSource":False})
    init=event("initialized",10)
    report["initializedEvent"]=init.get("event")=="initialized"
    bp=reply(send("setBreakpoints",{"source":{"path":args.source},
        "breakpoints":[{"line":5}],"sourceModified":False}),10)
    report["setBreakpointsOk"]=bp.get("success",False)
    report["breakpointVerified"]=[x.get("verified",False) for x in bp.get("body",{}).get("breakpoints",[])]
    reply(send("setExceptionBreakpoints",{"filters":[]}),10)
    cfg=reply(send("configurationDone",{}),10)
    report["configurationDoneOk"]=cfg.get("success",False)
    report["launchOk"]=reply(launch_seq,7).get("success",False)
    stopped=event("stopped",10)
    report["stopped"]=stopped.get("event")=="stopped"
    if report["stopped"]:
        thr=reply(send("threads",{}),10)
        threads=thr.get("body",{}).get("threads",[])
        tid=stopped.get("body",{}).get("threadId") or (threads[0]["id"] if threads else 1)
        stack=reply(send("stackTrace",{"threadId":tid,"startFrame":0,"levels":10}),10)
        frames=stack.get("body",{}).get("stackFrames",[])
        report["stackFrames"]=len(frames)
        refs=[(f.get("source") or {}) for f in frames]
        report["stackSourceRefs"]=[x.get("sourceReference",0) for x in refs]
        report["stackSourcePaths"]=[os.path.basename(x.get("path") or "") for x in refs]
        if refs:
            s=refs[0]; ref=s.get("sourceReference",0)
            sr=reply(send("source",{"source":{"path":s.get("path") or args.source,
                "sourceReference":ref},"sourceReference":ref}),10)
            report["sourceRequestOk"]=sr.get("success",False)
            report["sourceContentChars"]=len(sr.get("body",{}).get("content",""))
            report["sourceMessage"]=sr.get("message","")
    else:report["stoppedMessage"]=stopped
except Exception as e:
    report["error"]=type(e).__name__+":"+str(e)[:400]
finally:
    report["elapsedMs"]=round((time.monotonic()-start)*1000,2)
    report["adapterAliveAtEnd"]=proc.poll() is None
    try:
        if proc.poll() is None:
            send("disconnect",{"restart":False,"terminateDebuggee":True})
            proc.wait(timeout=2)
    except Exception:pass
    try:proc.kill()
    except Exception:pass
    try:proc.wait(timeout=2)
    except Exception:pass
    report["dapMessages"]=[{"type":x.get("type"),"command":x.get("command"),"event":x.get("event"),
        "success":x.get("success"),"message":str(x.get("message",""))[:100]} for x in log[:60]]
    report["adapterExitCode"]=proc.returncode
    with open(args.output,"a",encoding="utf-8") as f:
        f.write(json.dumps(report,separators=(",",":"))+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="dapMessages"}))
