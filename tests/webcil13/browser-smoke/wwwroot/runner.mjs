// Independent .NET 11 CoreCLR browser-WASM diagnostic runner.
// Instruments Node failure paths to distinguish an exception from process exit.
import { dotnet } from './_framework/dotnet.js';
const mode = process.env.WEBCIL13_MODE || 'smoke';
process.on('exit', code => console.log('WEBCIL13_NODE_EXIT_EVENT=' + code));
process.on('uncaughtExceptionMonitor', error =>
  console.error('WEBCIL13_NODE_UNCAUGHT=' + String(error?.stack || error)));
process.on('unhandledRejection', error => {
  console.error('WEBCIL13_NODE_REJECTION=' + String(error?.stack || error));
  process.exitCode = 73;
});
const previousExit = process.exit;
process.exit = function(code) {
  console.error('WEBCIL13_EXPLICIT_EXIT=' + code);
  console.error('WEBCIL13_EXIT_CALLER=' + new Error('exit trace').stack);
  return previousExit.call(process, code);
};
// Post-load passive observation of the synthetic in-range fixture in this
// process's *own* WebAssembly linear memory. Never disclose heap contents.
function inspectInRangeCanary(runtime) {
  try {
    const raw = runtime.INTERNAL?.GetDotNetRuntimeHeap?.();
    let bytes = null;
    if (raw instanceof Uint8Array) bytes = raw;
    else if (raw instanceof ArrayBuffer) bytes = new Uint8Array(raw);
    else if (ArrayBuffer.isView(raw)) bytes = new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    else if (raw?.buffer instanceof ArrayBuffer) bytes = new Uint8Array(raw.buffer);
    console.log('WEBCIL13_HEAP_VIEW_TYPE=' + Object.prototype.toString.call(raw));
    console.log('WEBCIL13_HEAP_VIEW_READABLE=' + Boolean(bytes));
    if (!bytes) return;
    const length = Math.min(bytes.length, 512 * 1024 * 1024);
    let candidateCount = 0;
    let baseCorrelations = 0;
    let unchangedTargets = 0;
    for (let at = 0; at + 256 < length; ) {
      const hit = bytes.indexOf(0x57, at);
      if (hit < 0 || hit + 256 >= length) break;
      at = hit + 1;
      if (bytes[hit + 1] !== 0x62 || bytes[hit + 2] !== 0x49 ||
          bytes[hit + 3] !== 0x4c || bytes[hit + 4] !== 1 ||
          bytes[hit + 8] !== 1 || bytes[hit + 10] !== 1 ||
          bytes[hit + 28] !== 1 ||
          bytes[hit + 32] !== 32 || bytes[hit + 36] !== 64 ||
          bytes[hit + 40] !== 32 || bytes[hit + 44] !== 64 ||
          bytes[hit + 64] !== 128 || bytes[hit + 68] !== 10 ||
          bytes[hit + 73] !== 0x30) continue;
      candidateCount++;
      const value = new DataView(bytes.buffer, bytes.byteOffset + hit + 128, 4).getUint32(0, true);
      if (value === (hit >>> 0)) baseCorrelations++;
      if (value === 0) unchangedTargets++;
    }
    console.log('WEBCIL13_HEAP_CANDIDATES=' + candidateCount);
    console.log('WEBCIL13_RELOCATED_BASE_CORRELATIONS=' + baseCorrelations);
    console.log('WEBCIL13_UNMODIFIED_CANDIDATES=' + unchangedTargets);
    console.log('WEBCIL13_PASSIVE_CHECK_NOT_PROOF_OF_OOB=true');
  } catch (error) {
    console.error('WEBCIL13_HEAP_VIEW_INSPECTION_ERROR=' + String(error?.message || error));
  }
}

console.log('WEBCIL13_BOOT_MODE=' + mode);
try {
  const runtime = await dotnet.withEnvironmentVariable('WEBCIL13_MODE', mode).create();
  console.log('WEBCIL13_RUNTIME_MODE=' + mode);
  console.log('WEBCIL13_RUNTIME_CORECLR_HEAP_API=' +
    (typeof runtime.INTERNAL?.GetDotNetRuntimeHeap === 'function'));
  const exitCode = await runtime.runMain();
  if (mode === 'inrange') inspectInRangeCanary(runtime);
  console.log('WEBCIL13_RUNTIME_MAIN_EXIT=' + exitCode);
  process.exitCode = exitCode;
} catch (error) {
  console.error('WEBCIL13_RUNMAIN_THROW=' + String(error?.stack || error));
  process.exitCode = 74;
}
