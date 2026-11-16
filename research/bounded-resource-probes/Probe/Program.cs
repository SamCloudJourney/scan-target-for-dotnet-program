using System.Buffers;
using System.Diagnostics;
using System.IO.Compression;
using System.IO.Pipelines;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Mono.Cecil;
using Microsoft.DiaSymReader;

const int MaxFormBytes = 524_288;
const int MaxDeclBytes = 8 * 1024 * 1024;
if (args.Length < 2)
{
    Console.Error.WriteLine("Usage: Probe form SIZE STEP | cecil DECLARED SAMPLE_DLL | cecil-model DECLARED | diasym-model DECLARED");
    return 2;
}

string mode = args[0];
int declared = int.Parse(args[1]);
if (mode == "form" ? declared is < 1 or > MaxFormBytes : declared is < 1 or > MaxDeclBytes)
{
    Console.Error.WriteLine("Bounded test rejected: size outside allowed range.");
    return 2;
}

int step = mode == "form" ? int.Parse(args[2]) : 0;
if (mode == "form" && (step < 1 || step > 256))
{
    Console.Error.WriteLine("Bounded test rejected: step outside allowed range.");
    return 2;
}

string status = "ok", exception = "", detail = "";
long before = GC.GetAllocatedBytesForCurrentThread();
using var process = Process.GetCurrentProcess();
TimeSpan cpuBefore = process.TotalProcessorTime;
var sw = Stopwatch.StartNew();
try
{
    switch (mode)
    {
        case "inspect":
            var parserType = typeof(FormPipeReader);
            var parsers = parserType.GetMethods(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
                .Where(m => m.Name == "ParseFormValues").ToArray();
            var argsText = string.Join(" / ", parsers.Select(m =>
                "(" + string.Join(",", m.GetParameters().Select(p => p.ParameterType.FullName)) + ")"));
            detail = "assembly=" + parserType.Assembly.GetName().Version +
                     ";module_mvid=" + parserType.Module.ModuleVersionId +
                     ";parse_signatures=" + argsText +
                     ";has_ref_long_scannedLength=" + parsers.Any(m => m.GetParameters()
                         .Any(p => p.ParameterType == typeof(long).MakeByRefType()));
            break;
        case "form":
            var input = Encoding.ASCII.GetBytes("x=" + new string('v', declared));
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8)))
            {
                var testReader = new PrefixReader(input, step);
                var form = new FormPipeReader(testReader, Encoding.UTF8)
                {
                    KeyLengthLimit = 2_048,
                    ValueLengthLimit = 524_288,
                    ValueCountLimit = 4
                };
                var result = form.ReadFormAsync(cts.Token).GetAwaiter().GetResult();
                if (!result.TryGetValue("x", out var value) || value.ToString().Length != declared)
                    throw new InvalidDataException("Form output mismatch");
                detail = "read_calls=" + testReader.ReadCalls;
            }
            break;
        case "cecil":
            if (args.Length < 3) throw new ArgumentException("Missing controlled sample DLL");
            var bytes = File.ReadAllBytes(args[2]);
            using (var image = new System.Reflection.PortableExecutable.PEReader(new MemoryStream(bytes)))
            {
                var debug = image.ReadDebugDirectory().FirstOrDefault(
                    x => x.Type == System.Reflection.PortableExecutable.DebugDirectoryEntryType.EmbeddedPortablePdb);
                if (debug.Type != System.Reflection.PortableExecutable.DebugDirectoryEntryType.EmbeddedPortablePdb)
                    throw new InvalidDataException("Controlled sample has no embedded PDB");
                int sizeField = checked(debug.DataPointer + 4);
                if (sizeField + 4 > bytes.Length) throw new InvalidDataException("Invalid embedded PDB directory");
                BitConverter.GetBytes(declared).CopyTo(bytes, sizeField);
                detail = "embedded_pdb_data_offset=" + debug.DataPointer;
            }
            var temp = Path.Combine(Path.GetTempPath(), "bounded-" + Guid.NewGuid().ToString("N") + ".dll");
            try
            {
                File.WriteAllBytes(temp, bytes);
                using var module = ModuleDefinition.ReadModule(temp, new ReaderParameters { ReadSymbols = true });
                detail += ";symbols_read=" + module.HasSymbols;
            }
            finally { File.Delete(temp); }
            break;
        case "cecil-model":
            byte[] uncompressedPdb = new byte[256];
            byte[] compressedPdb = Compress(uncompressedPdb);
            using (var source = new MemoryStream())
            {
                source.Write(Encoding.ASCII.GetBytes("MPDB"));
                source.Write(BitConverter.GetBytes(declared));
                source.Write(compressedPdb);
                source.Position = 0;
                using var binary = new BinaryReader(source, Encoding.ASCII, leaveOpen: true);
                binary.ReadInt32(); // exact source-code behavior: signature is skipped
                int length = binary.ReadInt32();
                using var output = new MemoryStream(length);
                using (var deflate = new DeflateStream(source, CompressionMode.Decompress, leaveOpen: true))
                    deflate.CopyTo(output);
                detail = "actual_output=" + output.Length + ";declared=" + length +
                         ";equality_checked=false";
            }
            break;
        case "diasym-package":
            using (var sourceDoc = new MemoryStream())
            {
                sourceDoc.Write(BitConverter.GetBytes(declared));
                sourceDoc.Write(Compress(new byte[256]));
                var syntheticDocument = new SyntheticDocument(sourceDoc.ToArray());
                var extracted = syntheticDocument.GetEmbeddedSource();
                detail = "actual_output=" + extracted.Count +
                         ";consumer=published_Microsoft.DiaSymReader_3.0.0_extension_with_mock_document";
            }
            break;
        case "diasym-model":
            byte[] sourceBytes = new byte[256];
            byte[] deflated = Compress(sourceBytes);
            using (var raw = new MemoryStream())
            {
                raw.Write(BitConverter.GetBytes(declared));
                raw.Write(deflated);
                byte[] blob = raw.ToArray();
                int uncompressedLength = BitConverter.ToInt32(blob, 0);
                // This reproduces the source's allocation ordering, NOT a native DiaSymReader PDB reader.
                var uncompressedBytes = new byte[uncompressedLength];
                using var compressed = new MemoryStream(blob, sizeof(int), blob.Length - sizeof(int));
                using var inflater = new DeflateStream(compressed, CompressionMode.Decompress);
                int position = 0;
                while (true)
                {
                    int got = inflater.Read(uncompressedBytes, position, uncompressedBytes.Length - position);
                    if (got == 0) break;
                    position += got;
                }
                if (position != uncompressedBytes.Length || inflater.ReadByte() != -1)
                    throw new InvalidDataException("Exact-output mismatch after allocation");
                detail = "actual_output=" + position;
            }
            break;
        default: throw new ArgumentException("Unknown mode");
    }
}
catch (Exception e)
{
    status = "exception";
    exception = e.GetType().FullName ?? e.GetType().Name;
    detail += ";message=" + e.Message;
}
sw.Stop();
long allocated = GC.GetAllocatedBytesForCurrentThread() - before;
process.Refresh();
Console.WriteLine(JsonSerializer.Serialize(new
{
    mode, declared, step, framework = RuntimeInformation.FrameworkDescription,
    status, exception, detail,
    elapsed_ms = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
    cpu_ms = Math.Round((process.TotalProcessorTime - cpuBefore).TotalMilliseconds, 3),
    allocated_bytes = allocated,
    working_set_bytes = process.WorkingSet64
}));
return 0;

static byte[] Compress(byte[] bytes)
{
    using var output = new MemoryStream();
    using (var deflater = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        deflater.Write(bytes, 0, bytes.Length);
    return output.ToArray();
}

// A controlled, in-memory PipeReader: each read reveals STEP additional bytes,
// while the reader correctly preserves the incomplete prefix (AdvanceTo consumes none).
// This models the parser's worst-case read fragmentation without a network endpoint.
sealed class PrefixReader : PipeReader
{
    private readonly byte[] _bytes;
    private readonly int _step;
    private int _visible;
    public int ReadCalls { get; private set; }
    public PrefixReader(byte[] bytes, int step) { _bytes = bytes; _step = step; }
    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _visible = Math.Min(_visible + _step, _bytes.Length);
        ReadCalls++;
        return ValueTask.FromResult(new ReadResult(
            new ReadOnlySequence<byte>(_bytes, 0, _visible),
            isCanceled: false, isCompleted: _visible == _bytes.Length));
    }
    public override bool TryRead(out ReadResult result) { result = default; return false; }
    public override void AdvanceTo(SequencePosition consumed) { }
    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) { }
    public override void CancelPendingRead() { }
    public override void Complete(Exception? exception = null) { }
}


// A strictly local ISymUnmanagedDocument adapter allows direct invocation of the
// Microsoft.DiaSymReader package's actual managed GetEmbeddedSource extension.
// This does NOT open or validate a PDB, instantiate the native Windows reader,
// or prove that untrusted PDB bytes pass the native reader's validation gates.
sealed class SyntheticDocument : ISymUnmanagedDocument
{
    private readonly byte[] _source;
    public SyntheticDocument(byte[] source) { _source = source; }
    public int GetUrl(int bufferLength, out int count, char[] url) { count = 0; return 0; }
    public int GetDocumentType(ref Guid value) => 0;
    public int GetLanguage(ref Guid value) => 0;
    public int GetLanguageVendor(ref Guid value) => 0;
    public int GetChecksumAlgorithmId(ref Guid value) => 0;
    public int GetChecksum(int bufferLength, out int count, byte[] checksum) { count = 0; return 0; }
    public int FindClosestLine(int line, out int closestLine) { closestLine = line; return 0; }
    public int HasEmbeddedSource(out bool value) { value = true; return 0; }
    public int GetSourceLength(out int length) { length = _source.Length; return 0; }
    public int GetSourceRange(int startLine, int startColumn, int endLine, int endColumn,
                              int bufferLength, out int count, byte[] source)
    {
        count = Math.Min(bufferLength, _source.Length);
        Array.Copy(_source, source, count);
        return 0;
    }
}
