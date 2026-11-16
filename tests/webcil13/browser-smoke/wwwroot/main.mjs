// Minimal .NET browser-wasm boot. No DOM or network.
import { dotnet } from './_framework/dotnet.js';
const { runMain } = await dotnet.create();
const exitCode = await runMain();
console.log('WEBCIL13_RUNTIME_MAIN_EXIT=' + exitCode);
