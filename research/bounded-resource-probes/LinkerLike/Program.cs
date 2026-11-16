using System.Diagnostics;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text.Json;
using Mono.Cecil;
using Mono.Cecil.Cil;

if (args.Length != 3 || !int.TryParse(args[1], out int declared) ||
    (declared != -1 && (declared < 1 || declared > 8 * 1024 * 1024)) ||
    args[2] is not ("disabled" or "direct" or "linker"))
{
    Console.Error.WriteLine("Usage: LinkerLike controlled.dll DECLARED(1..8388608|-1) disabled|direct|linker");
    return 2;
}
const int MaxPe = 128 * 1024;
var source = File.ReadAllBytes(args[0]);
if (source.Length > MaxPe) throw new InvalidDataException("Only a small investigator-authored PE is allowed.");
byte[] input = (byte[])source.Clone();
using (var pe = new PEReader(new MemoryStream(input)))
{
    var debug = pe.ReadDebugDirectory().FirstOrDefault(d => d.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
    if (debug.Type != DebugDirectoryEntryType.EmbeddedPortablePdb || debug.DataPointer < 0 ||
        debug.DataPointer + 8 > input.Length ||
        !input.AsSpan(debug.DataPointer, 4).SequenceEqual("MPDB"u8))
        throw new InvalidDataException("Controlled input must have an embedded PDB.");
    BitConverter.GetBytes(declared).CopyTo(input, debug.DataPointer + 4);
}

string path = Path.Combine(Path.GetTempPath(), "self-generated-" + Guid.NewGuid().ToString("N") + ".dll");
string status = "ok", error = "", providerType = "";
long before = GC.GetTotalAllocatedBytes();
var process = Process.GetCurrentProcess();
var cpu0 = process.TotalProcessorTime;
bool hasSymbols = false;
var timer = Stopwatch.StartNew();
try
{
    File.WriteAllBytes(path, input);
    if (args[2] == "direct")
    {
        using var module = ModuleDefinition.ReadModule(path, new ReaderParameters { ReadSymbols = true });
        hasSymbols = module.HasSymbols;
    }
    else
    {
        using var module = ModuleDefinition.ReadModule(path, new ReaderParameters { ReadSymbols = false });
        if (args[2] == "linker")
        {
            // Reproduces LinkContext.SafeReadSymbols' reader-selection and catch boundary,
            // but does NOT instantiate the actual linker tool or claim a default service exposure.
            var provider = new DefaultSymbolReaderProvider(false);
            ISymbolReader? symbols = null;
            try
            {
                symbols = provider.GetSymbolReader(module, path);
                providerType = symbols?.GetType().FullName ?? "null";
                if (symbols != null)
                {
                    try { module.ReadSymbols(symbols); }
                    catch (Exception ex) { status = "symbol-error-caught"; error = ex.GetType().Name; symbols.Dispose(); }
                }
            }
            catch (Exception ex) { status = "provider-error-caught"; error = ex.GetType().Name; }
        }
        hasSymbols = module.HasSymbols;
    }
}
catch (Exception ex) { status = "exception"; error = ex.GetType().Name; }
finally { File.Delete(path); }
timer.Stop();
process.Refresh();
Console.WriteLine(JsonSerializer.Serialize(new {
    test="linker-like-symbol-reader-selection", declared, mode=args[2], status, error,
    hasSymbols, providerType, inputBytes = input.Length,
    allocatedBytes = GC.GetTotalAllocatedBytes() - before,
    elapsedMs = Math.Round(timer.Elapsed.TotalMilliseconds,3),
    cpuMs = Math.Round((process.TotalProcessorTime-cpu0).TotalMilliseconds,3),
    workingSetBytes = process.WorkingSet64,
    framework=RuntimeInformation.FrameworkDescription
}));
return 0;
