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
console.log('WEBCIL13_BOOT_MODE=' + mode);
try {
  const runtime = await dotnet.withEnvironmentVariable('WEBCIL13_MODE', mode).create();
  console.log('WEBCIL13_RUNTIME_MODE=' + mode);
  console.log('WEBCIL13_RUNTIME_CORECLR_HEAP_API=' +
    (typeof runtime.INTERNAL?.GetDotNetRuntimeHeap === 'function'));
  const exitCode = await runtime.runMain();
  console.log('WEBCIL13_RUNTIME_MAIN_EXIT=' + exitCode);
  process.exitCode = exitCode;
} catch (error) {
  console.error('WEBCIL13_RUNMAIN_THROW=' + String(error?.stack || error));
  process.exitCode = 74;
}
