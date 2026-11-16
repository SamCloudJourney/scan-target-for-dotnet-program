using System.Diagnostics;
using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text.Json;
using Mono.Cecil;

const int MaxInflated = 2 * 1024 * 1024;
const int MaxPayload = 128 * 1024;
bool guarded = args.Length == 5 && args[4] == "guarded";
if ((args.Length != 4 && !guarded) || !int.TryParse(args[1], out int declared) ||
    !int.TryParse(args[2], out int appendZeros) || !bool.TryParse(args[3], out bool symbols) ||
    declared is < 1 or > 8 * 1024 * 1024 ||
    appendZeros is < 0 or > 1024 * 1024)
{
    Console.Error.WriteLine("Usage: CecilExpand Sample.dll DECLARED [0..1048576 appended zeros] [true|false symbols]");
    return 2;
}
byte[] original = File.ReadAllBytes(args[0]);
if (original.Length > MaxPayload) throw new InvalidDataException("Controlled sample only: 128 KiB input cap");

byte[] mutated;
int originalPdbSize, newActualInflatedPdb, debugFileOffset, originalCompressed;
using (var image = new PEReader(new MemoryStream(original)))
{
    var header = image.PEHeaders.PEHeader ?? throw new InvalidDataException("Missing PE header");
    var entries = image.ReadDebugDirectory();
    int index = -1;
    for (int n = 0; n < entries.Length; n++)
        if (entries[n].Type == DebugDirectoryEntryType.EmbeddedPortablePdb) { index = n; break; }
    if (index < 0) throw new InvalidDataException("Not self-generated embedded-PDB PE");
    var dir = entries[index];
    if (dir.DataPointer < 0 || dir.DataSize < 9 || dir.DataPointer + dir.DataSize > original.Length)
        throw new InvalidDataException("Invalid source debug range");
    if (!original.AsSpan(dir.DataPointer, 4).SequenceEqual("MPDB"u8))
        throw new InvalidDataException("Missing embedded-PDB signature");

    originalPdbSize = BitConverter.ToInt32(original, dir.DataPointer + 4);
    originalCompressed = dir.DataSize - 8;
    if (originalPdbSize is < 1 or > 64 * 1024) throw new InvalidDataException("Unexpected original PDB size");
    byte[] inflation;
    using (var input = new MemoryStream(original, dir.DataPointer + 8, originalCompressed, false))
    using (var deflate = new DeflateStream(input, CompressionMode.Decompress))
    using (var output = new MemoryStream())
    {
        deflate.CopyTo(output);
        if (output.Length > 64 * 1024) throw new InvalidDataException("Original PDB cap");
        output.Write(new byte[appendZeros]);
        if (output.Length > MaxInflated) throw new InvalidDataException("Synthetic output cap");
        inflation = output.ToArray();
    }
    newActualInflatedPdb = inflation.Length;
    byte[] compressed;
    using (var result = new MemoryStream())
    {
        using (var zipper = new DeflateStream(result, CompressionLevel.Optimal, leaveOpen:true))
            zipper.Write(inflation);
        compressed = result.ToArray();
    }
    using var chunk = new MemoryStream();
    chunk.Write("MPDB"u8);
    chunk.Write(BitConverter.GetBytes(declared));
    chunk.Write(compressed);
    byte[] newPayload = chunk.ToArray();

    int debugRva = header.DebugTableDirectory.RelativeVirtualAddress;
    var section = image.PEHeaders.SectionHeaders.FirstOrDefault(s =>
        debugRva >= s.VirtualAddress && debugRva - s.VirtualAddress < s.SizeOfRawData);
    if (section.SizeOfRawData == 0) throw new InvalidDataException("Debug directory unavailable");
    debugFileOffset = checked(section.PointerToRawData + debugRva - section.VirtualAddress + index * 28);
    if (debugFileOffset + 28 > original.Length) throw new InvalidDataException("Debug entry invalid");
    int newDataPointer = original.Length;
    if (newDataPointer + newPayload.Length > MaxPayload) throw new InvalidDataException("Compressed output exceeded input cap");

    mutated = new byte[newDataPointer + newPayload.Length];
    original.CopyTo(mutated, 0);
    newPayload.CopyTo(mutated, newDataPointer);
    // IMAGE_DEBUG_DIRECTORY + 16 = SizeOfData, + 24 = PointerToRawData;
    // Mono.Cecil's ImageReader resolves PointerToRawData explicitly.
    BitConverter.GetBytes(newPayload.Length).CopyTo(mutated, debugFileOffset + 16);
    BitConverter.GetBytes(newDataPointer).CopyTo(mutated, debugFileOffset + 24);
}

long before = GC.GetTotalAllocatedBytes();
long wsBefore = Environment.WorkingSet;
string status = "ok", error = "";
bool parsedSymbols = false;
var sw = Stopwatch.StartNew();
try
{
    if (guarded)
    {
        // Investigator-only fail-closed policy, not a claim about shipped Mono.Cecil.
        const int AbsoluteOutputLimit = 256 * 1024;
        using var preflight = new PEReader(new MemoryStream(mutated));
        var debug = preflight.ReadDebugDirectory().First(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
        if (debug.DataSize < 9 || debug.DataPointer < 0 || debug.DataPointer + debug.DataSize > mutated.Length)
            throw new InvalidDataException("Embedded PDB bounds invalid");
        var embedded = mutated.AsSpan(debug.DataPointer, debug.DataSize);
        if (!embedded[..4].SequenceEqual("MPDB"u8))
            throw new InvalidDataException("Embedded PDB signature mismatch");
        int prefix = BitConverter.ToInt32(embedded[4..8]);
        if (prefix < 1 || prefix > AbsoluteOutputLimit)
            throw new InvalidDataException("Guarded rejection: declared PDB size outside 256 KiB budget");
        using var compressed = new MemoryStream(mutated, debug.DataPointer + 8, debug.DataSize - 8, writable: false);
        using var inflater = new DeflateStream(compressed, CompressionMode.Decompress);
        byte[] slice = new byte[4096];
        int actual = 0, read;
        while ((read = inflater.Read(slice)) > 0)
        {
            actual = checked(actual + read);
            if (actual > AbsoluteOutputLimit)
                throw new InvalidDataException("Guarded rejection: inflated PDB output over 256 KiB budget");
        }
        if (actual != prefix)
            throw new InvalidDataException("Guarded rejection: declared/actual PDB size mismatch");
    }
    using var stream = new MemoryStream(mutated);
    using var module = ModuleDefinition.ReadModule(stream, new ReaderParameters { ReadSymbols = symbols });
    parsedSymbols = module.HasSymbols;
}
catch (Exception ex) { status = "exception"; error = ex.GetType().Name; }
sw.Stop();

Console.WriteLine(JsonSerializer.Serialize(new {
    mode = "cecil-recompressed-real-pe", framework = RuntimeInformation.FrameworkDescription,
    status, error, symbols, guarded, parsedSymbols, declared,
    originalPeBytes = original.Length, newPeBytes = mutated.Length,
    originalPdbSize, originalCompressed, appendedZeroBytes = appendZeros,
    newActualInflatedPdb, debugFileOffset,
    elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
    allocatedBytes = GC.GetTotalAllocatedBytes() - before,
    workingSetBefore = wsBefore, workingSetAfter = Environment.WorkingSet
}));
return 0;
