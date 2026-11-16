// Chromium CDP test: local-only navigation, synthetic secrets excluded.
import fs from "node:fs/promises";
const output=process.argv[2]||"browser.json";
const major=Number(process.argv[3]);
const app="http://127.0.0.1:5200";
const receiver="http://127.0.0.2:5207";
const response=await fetch("http://127.0.0.1:5221/json/new?"+encodeURIComponent(app+"/healthz"),{method:"PUT"});
if(!response.ok)throw Error("Cannot create Chrome CDP tab");
const tab=await response.json();
const ws=new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{
  const t=setTimeout(()=>reject(Error("CDP handshake timed out")),8000);
  ws.addEventListener("open",()=>{clearTimeout(t);resolve()},{once:true});
  ws.addEventListener("error",()=>{clearTimeout(t);reject(Error("CDP websocket error"))},{once:true});
});
const callbacks=new Map();
let counter=0;
const urls=[];
ws.addEventListener("message",event=>{
  let msg;
  try{msg=JSON.parse(event.data)}catch{return}
  if(msg.method==="Network.requestWillBeSent"){
    const u=msg.params?.request?.url||"";
    if(u.startsWith(app) || u.startsWith(receiver))
      urls.push({url:u,redirect_status:msg.params?.redirectResponse?.status??null});
  }
  if(typeof msg.id==="number"){
    const task=callbacks.get(msg.id);
    if(!task)return;
    callbacks.delete(msg.id);
    if(msg.error)task.reject(Error(JSON.stringify(msg.error)));
    else task.resolve(msg.result||{});
  }
});
function cmd(method,params={}){
  return new Promise((resolve,reject)=>{
    const id=++counter;
    callbacks.set(id,{resolve,reject});
    ws.send(JSON.stringify({id,method,params}));
    setTimeout(()=>{if(callbacks.has(id)){callbacks.delete(id);reject(Error("CDP timeout "+method));}},10000);
  });
}
const sleep=ms=>new Promise(ok=>setTimeout(ok,ms));
async function navigate(url){
  await cmd("Page.navigate",{url});
  await sleep(1000);
}
function containsAuth(cookies){
  return (cookies||[]).some(c=>c.name==="pass6.auth");
}
const checks={};
try{
  await cmd("Page.enable");
  await cmd("Network.enable");
  const browserInfo=await cmd("Browser.getVersion");
  await cmd("Network.setExtraHTTPHeaders",{
    headers:{"X-Forwarded-Prefix":"/;Domain=evil.example.test"}});
  await navigate(app+"/cookie/issue?user=alice");
  const all=(await cmd("Network.getAllCookies")).cookies||[];
  const restricted=all.filter(c=>c.name==="pass6.auth");
  const root=(await cmd("Network.getCookies",{urls:[app+"/auth/export"]})).cookies||[];
  const encoded=(await cmd("Network.getCookies",{urls:[app+"/%3BDomain=evil.example.test/auth/export"]})).cookies||[];
  const other=(await cmd("Network.getCookies",{urls:[receiver+"/receiver"]})).cookies||[];
  checks.host_only_cookie=restricted.length===1 && restricted[0].domain==="127.0.0.1";
  checks.httponly_cookie=restricted.length===1 && restricted[0].httpOnly;
  checks.cookie_not_root_scope=!containsAuth(root);
  checks.cookie_on_encoded_path=containsAuth(encoded);
  checks.cookie_not_other_hostname=!containsAuth(other);
  await cmd("Network.setExtraHTTPHeaders",{headers:{}});
  // A normal, host-only sign-in cookie exists only for the local app host.
  await navigate(app+"/auth/login?user=bob");
  const before=(await fetch(receiver+"/_events")).json();
  const browserBefore=(await before).events.length;
  await navigate(app+"/legacy//127.0.0.2:5207/receiver?marker=PUBLIC-ONLY");
  const after=await (await fetch(receiver+"/_events")).json();
  const hits=after.events.slice(browserBefore);
  const escaped=hits.some(x=>x.path.startsWith("/receiver?marker=PUBLIC-ONLY"));
  checks.unsafe_rewrite_cross_origin_version=escaped===(major===10);
  checks.redirect_never_leaks_fixture_session_cookie=hits.every(x=>
    !x.cookie_names.includes("pass6.auth"));
  const beforeSafe=after.events.length;
  await navigate(app+"/safe//127.0.0.2:5207/receiver?marker=SAFE-ONLY");
  const afterSafe=await (await fetch(receiver+"/_events")).json();
  checks.safe_rewrite_does_not_redirect=afterSafe.events.length===beforeSafe;
  const info={
    suite:"browser-cookie-redirect",
    browser_product:browserInfo.product,
    framework_major:major,
    cookie_metadata:restricted.map(c=>({name:c.name,domain:c.domain,path:c.path,
      sameSite:c.sameSite,httpOnly:c.httpOnly,secure:c.secure})),
    navigator_requests:urls,
    receiver_events:afterSafe.events,
    checks,
    passed:Object.values(checks).filter(Boolean).length,
    total:Object.keys(checks).length
  };
  await fs.writeFile(output,JSON.stringify(info,null,2));
  console.log(JSON.stringify({browser:info.browser_product,passed:info.passed,total:info.total,
    checks:info.checks,receiver_events:info.receiver_events},null,2));
  if(!Object.values(checks).every(Boolean))process.exitCode=1;
}finally{ws.close()}
