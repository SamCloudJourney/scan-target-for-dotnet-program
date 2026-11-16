// No npm packages or external network access. Chrome DevTools Protocol via loopback.
import fs from "node:fs/promises";

const output = process.argv[2] ?? "chrome-cookie-result.json";
const host = "127.0.0.1";
const appPort = 5100;
const cdpPort = 5121;
const origin = "http://" + host + ":" + appPort;
const target = origin + "/cookie/issue?user=alice";

const put = await fetch("http://" + host + ":" + cdpPort + "/json/new?" + encodeURIComponent(origin + "/healthz"), {
  method: "PUT",
});
if (!put.ok) throw new Error("CDP target could not be created: HTTP " + put.status);
const tab = await put.json();
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error("Chrome CDP handshake timed out")), 8000);
  ws.addEventListener("open", () => { clearTimeout(timeout); resolve(); }, { once: true });
  ws.addEventListener("error", e => { clearTimeout(timeout); reject(new Error("Chrome WebSocket failure")); }, { once: true });
});
let id = 0;
const pending = new Map();
ws.addEventListener("message", event => {
  let msg;
  try { msg = JSON.parse(event.data); } catch { return; }
  if (typeof msg.id !== "number") return;
  const task = pending.get(msg.id);
  if (!task) return;
  pending.delete(msg.id);
  if (msg.error) task.reject(new Error(JSON.stringify(msg.error)));
  else task.resolve(msg.result || {});
});
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const number = ++id;
    pending.set(number, {resolve, reject});
    ws.send(JSON.stringify({id: number, method, params}));
    setTimeout(() => {
      if (pending.has(number)) {
        pending.delete(number);
        reject(new Error("CDP request timeout: " + method));
      }
    }, 8000);
  });
}
const sleep = ms => new Promise(ok => setTimeout(ok, ms));
const safeCookie = c => ({
  name: c.name, domain: c.domain, path: c.path, secure: c.secure,
  httpOnly: c.httpOnly, sameSite: c.sameSite
});
try {
  await send("Page.enable");
  await send("Network.enable");
  await send("Network.setExtraHTTPHeaders", {
    headers: {"X-Forwarded-Prefix": "/;Domain=example.test"}
  });
  await send("Page.navigate", {url: target});
  await sleep(1100);
  const all = (await send("Network.getAllCookies")).cookies || [];
  const root = (await send("Network.getCookies", {urls: [origin + "/whoami"]})).cookies || [];
  const encodedPath = (await send("Network.getCookies", {
    urls: [origin + "/%3BDomain=example.test/whoami"]
  })).cookies || [];
  const literalPath = (await send("Network.getCookies", {
    urls: [origin + "/;Domain=example.test/whoami"]
  })).cookies || [];
  const auth = all.filter(c => c.name === "impact.fixture.auth");
  const scope = (arr) => arr.some(c => c.name === "impact.fixture.auth");
  const checks = {
    "chrome_stored_fixture_cookie": auth.length === 1,
    "chrome_host_only_no_foreign_domain": auth.length === 1 && auth[0].domain === host,
    "chrome_cookie_scope_not_root": !scope(root),
    "chrome_cookie_scope_percent_encoded_path": scope(encodedPath),
    "chrome_cookie_scope_not_literal_semicolon_path": !scope(literalPath),
    "chrome_cookie_remains_httponly": auth.length === 1 && auth[0].httpOnly
  };
  const data = {
    browser: "Chrome/Chromium via DevTools Protocol",
    run_scope: "127.0.0.1 only",
    cookie_metadata: auth.map(safeCookie),
    cookie_scope: {
      root: scope(root), percent_encoded: scope(encodedPath),
      literal_semicolon: scope(literalPath)
    },
    checks,
    passed: Object.values(checks).filter(Boolean).length,
    total: Object.keys(checks).length
  };
  await fs.writeFile(output, JSON.stringify(data, null, 2));
  process.stdout.write(JSON.stringify(data, null, 2) + "\n");
  if (!Object.values(checks).every(Boolean)) process.exitCode = 1;
} finally {
  ws.close();
}
