// Headless Node runner for the actual published .NET browser-wasm bundle.
import { dotnet } from './_framework/dotnet.js';
const runtime = await dotnet.create();
console.log('WEBCIL13_RUNTIME_CORECLR_HEAP_API=' +
  (typeof runtime.INTERNAL?.GetDotNetRuntimeHeap === 'function'));
const exitCode = await runtime.runMain();
console.log('WEBCIL13_RUNTIME_MAIN_EXIT=' + exitCode);
process.exitCode = exitCode;
