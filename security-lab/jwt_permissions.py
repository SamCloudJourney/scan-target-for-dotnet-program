#!/usr/bin/env python3
"""First-create dotnet user-jwts key file permissions; synthetic local key only."""
import json,os,pathlib,stat,subprocess,tempfile,re,pwd
OUT=pathlib.Path(os.environ.get("BOUNDARY_OUTPUT","."))
OUT.mkdir(parents=True,exist_ok=True)
ROOT=pathlib.Path(tempfile.mkdtemp(prefix="userjwt-boundary-"))
ROOT.chmod(0o755)
def run(args,cwd,home,mode):
    env=dict(os.environ, HOME=str(home),DOTNET_CLI_HOME=str(home),XDG_CONFIG_HOME=str(home/".config"),
             DOTNET_CLI_TELEMETRY_OPTOUT="1",DOTNET_NOLOGO="1")
    def preexec(): os.umask(mode)
    try:
        p=subprocess.run(args,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                         text=True,timeout=130,preexec_fn=preexec)
        # Never store a synthetic JWT or key in a public CI log/artifact.
        return {"exit":p.returncode,"stdout_length":len(p.stdout),"output_mentions_token":("Token:" in p.stdout or "Token created" in p.stdout),"output_mentions_help":("Usage:" in p.stdout),"output_mentions_error":("Error:" in p.stdout or "error:" in p.stdout),"output_tail_redacted":"<CLI output suppressed; may contain synthetic JWT>"}
    except Exception as e: return {"exit":-999,"error":str(e)}
def readable_by_other_user(path):
    if subprocess.run(["which","sudo"],stdout=subprocess.DEVNULL).returncode!=0:return None
    command=["sudo","-n","-u","nobody","python3","-c",
             "import os,sys; p=sys.argv[1]; print('READABLE' if os.access(p,os.R_OK) else 'DENIED')",str(path)]
    try:
        p=subprocess.run(command,text=True,capture_output=True,timeout=15)
        return p.returncode==0 and p.stdout.strip()=="READABLE"
    except Exception: return None
results=[]
for name,umask in [("ordinary_umask_022",0o022),("strict_umask_077",0o077)]:
    home=ROOT/name
    home.mkdir(mode=0o755)
    app=home/"App"
    app.mkdir()
    proj=app/"App.csproj"
    proj.write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net11.0</TargetFramework></PropertyGroup></Project>')
    init=run(["dotnet","user-secrets","init","--project",str(proj)],app,home,umask)
    created=run(["dotnet","user-jwts","create","--project",str(proj),"--audience","https://localhost:5001"],app,home,umask)
    uid_match=re.search(r"<UserSecretsId>([^<]+)</UserSecretsId>",proj.read_text())
    uid=uid_match.group(1) if uid_match else ""
    fallback=pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)
    candidates=list(home.rglob("secrets.json"))
    for basedir in [fallback/".microsoft"/"usersecrets",fallback/".config",fallback/".local"/"share"]:
        if basedir.exists(): candidates+=list(basedir.rglob("secrets.json"))
    secrets=list(dict.fromkeys(p for p in candidates if not uid or uid in str(p)))
    inspected=[]
    for p in secrets:
        try:
            text=p.read_text()
            contains_signing_key= "SigningKeys" in text and "Value" in text
            mode_now=stat.S_IMODE(p.stat().st_mode)
            inspected.append({"relative_path":str(p.relative_to(home)) if p.is_relative_to(home) else str(p),"permissions":oct(mode_now),
                              "contains_synthetic_signing_key":contains_signing_key,
                              "group_or_other_readable":bool(mode_now & 0o044),
                              "readable_as_nobody":readable_by_other_user(p)})
        except Exception as e:inspected.append({"relative_path":str(p.relative_to(home)),"error":str(e)})
    results.append({"scenario":name,"umask":oct(umask),"has_user_secrets_id":bool(uid),"file_candidate_count":len(candidates),"init":init,"create":created,"keys":inspected})
report={"tests":results,"note":"No actual key material, JWT token, or signing secret included."}
(OUT/"jwt-permissions-results.json").write_text(json.dumps(report,indent=2))
for r in results:print(r["scenario"],"init",r["init"]["exit"],"create",r["create"]["exit"],"keys",r["keys"])
