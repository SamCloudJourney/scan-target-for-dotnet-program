// Independent headless .NET 11 CoreCLR browser-WASM boot.
// Run mode is explicitly selected for each fresh process; no external traffic.
import { dotnet } from './_framework/dotnet.js';
const mode = process.env.WEBCIL13_MODE || 'smoke';
const runtime = await dotnet.withEnvironmentVariable('WEBCIL13_MODE', mode).create();
console.log('WEBCIL13_RUNTIME_MODE=' + mode);
console.log('WEBCIL13_RUNTIME_CORECLR_HEAP_API=' +
  (typeof runtime.INTERNAL?.GetDotNetRuntimeHeap === 'function'));
const exitCode = await runtime.runMain();
console.log('WEBCIL13_RUNTIME_MAIN_EXIT=' + exitCode);
process.exitCode = exitCode;
