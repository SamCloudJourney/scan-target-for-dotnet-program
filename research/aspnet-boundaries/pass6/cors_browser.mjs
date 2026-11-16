import fs from "node:fs/promises";
const path=process.argv[2]||"cors-browser.json";
const base="http://127.0.0.1:5200", origin="http://127.0.0.1:5207";
const put=await fetch("http://127.0.0.1:5229/json/new?"+encodeURIComponent(origin+"/page"),{method:"PUT"});
if(!put.ok)throw Error("CDP target failed");
const tab=await put.json();
const ws=new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve,reject)=>{
 const timer=setTimeout(()=>reject(Error("CDP connect timeout")),9000);
 ws.addEventListener("open",()=>{clearTimeout(timer);resolve()},{once:true});
 ws.addEventListener("error",()=>{clearTimeout(timer);reject(Error("CDP error"))},{once:true});
});
const pending=new Map();let id=0;
ws.addEventListener("message",ev=>{
 let msg;try{msg=JSON.parse(ev.data)}catch{return}
 if(typeof msg.id!=="number")return;
 const job=pending.get(msg.id);if(!job)return;
 pending.delete(msg.id);
 if(msg.error)job.reject(Error(JSON.stringify(msg.error)));else job.resolve(msg.result||{});
});
function send(method,params={}){
 return new Promise((resolve,reject)=>{
  const number=++id;pending.set(number,{resolve,reject});
  ws.send(JSON.stringify({id:number,method,params}));
  setTimeout(()=>{if(pending.has(number)){pending.delete(number);reject(Error(method+" timeout"))}},9000);
 });
}
async function evalOnPage(code){
 const result=await send("Runtime.evaluate",{expression:code,awaitPromise:true,returnByValue:true});
 if(result.exceptionDetails)throw Error("Runtime.evaluate exception");
 return result.result?.value;
}
async function read(url,credentials){
 const expr="(async function(){try{const rsp=await fetch("+JSON.stringify(url)+", {mode:'cors',cache:'no-store',credentials:"+JSON.stringify(credentials)+"});const body=await rsp.text();return {ok:rsp.ok,status:rsp.status,body,type:rsp.type};}catch(err){return {blocked:true,error:String(err.name)}}})()";
 return await evalOnPage(expr);
}
try{
 await send("Page.enable");await send("Network.enable");
 await send("Page.navigate",{url:origin+"/page"});
 await new Promise(resolve=>setTimeout(resolve,1100));
 const current=await evalOnPage("location.origin");
 if(current!==origin)throw Error("Unexpected browsing origin "+current);
 const collision=await read(base+"/cache/public?a%3DB=","omit");
 const again=await read(base+"/cache/public?a%3DB=","omit");
 const negative=await read(base+"/cache/public?a%3DB=&uniquecontrol=yes","omit");
 const positive=await read(base+"/cache/public?a=B%3D","omit");
 const creds=await read(base+"/cache/public?a%3DB=","include");
 const checks={
  "separate_origin":current!==base,
  "collision_public_html_readable":collision.ok===true && collision.body.includes("public A"),
  "repeat_collision_readable":again.ok===true && again.body===collision.body,
  "normal_B_CORS_denies_external_script":negative.blocked===true && negative.error==="TypeError",
  "A_CORS_intentionally_allows_external_script":positive.ok===true && positive.body.includes("public A"),
  "credentialed_CORS_not_enabled":creds.blocked===true && creds.error==="TypeError"
 };
 const out={browser:(await send("Browser.getVersion")).product,scope:"all-loopback PUBLIC fixtures",
   origin,checks,passed:Object.values(checks).filter(Boolean).length,
   total:Object.keys(checks).length,observed:{collision,repeat:again,noncolliding_B:negative,original_A:positive,with_credentials:creds}};
 await fs.writeFile(path,JSON.stringify(out,null,2));
 console.log(JSON.stringify(out,null,2));
 if(out.passed!==out.total)process.exitCode=1;
}finally{ws.close()}
