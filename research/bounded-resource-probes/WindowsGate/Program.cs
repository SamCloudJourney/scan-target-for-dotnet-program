using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.DiaSymReader;

if ((args.Length != 1 && args.Length != 2) ||
    (args.Length == 2 && (!int.TryParse(args[1], out var _) || long.Parse(args[1]) < 0 || long.Parse(args[1]) > 8 * 1024 * 1024)))
{
    Console.Error.WriteLine("Usage: WindowsGate <self-generated.pdb> [0|1048576|8388608]");
    return 2;
}
int declared = args.Length == 2 ? int.Parse(args[1]) : 0;
var pdb = File.ReadAllBytes(args[0]);
if (pdb.Length > 1_048_576 || pdb.Length < 4 || !pdb.AsSpan(0, 4).SequenceEqual("BSJB"u8))
    throw new InvalidDataException("Only the investigator-generated small Portable PDB is accepted.");

int offset = -1, originalSize = -1, embeddedBlobLength = 0;
var sourceGuid = new Guid("0E8A571B-6926-466E-B4AD-8AB04611F5FE");
using (var stream = new MemoryStream(pdb))
using (var provider = MetadataReaderProvider.FromPortablePdbStream(stream, MetadataStreamOptions.LeaveOpen))
{
    var md = provider.GetMetadataReader();
    foreach (var doc in md.Documents)
    {
        int token = MetadataTokens.GetToken(doc);
        foreach (var infoHandle in md.GetCustomDebugInformation(MetadataTokens.EntityHandle(token)))
        {
            var info = md.GetCustomDebugInformation(infoHandle);
            if (md.GetGuid(info.Kind) != sourceGuid) continue;
            byte[] blob = md.GetBlobBytes(info.Value);
            if (blob.Length < 8) continue;
            int candidate = pdb.AsSpan().IndexOf(blob);
            if (candidate < 0) continue;
            offset = candidate;
            originalSize = BitConverter.ToInt32(blob);
            embeddedBlobLength = blob.Length;
            break;
        }
        if (offset >= 0) break;
    }
}
if (offset < 0) throw new InvalidDataException("No embedded source in controlled Portable PDB");
if (declared > 0) BitConverter.GetBytes(declared).CopyTo(pdb, offset);

long before = GC.GetTotalAllocatedBytes();
var sw = Stopwatch.StartNew();
string status = "ok", error = "", readerType = "";
int documentCount = -1, documentsCopied = -1, sourceLength = -1;
bool foundEmbedded = false;
try
{
    using var source = new MemoryStream(pdb);
    // Explicit factory for Windows reader / COM path, NOT managed PortablePdb SymBinder.
    var reader = SymUnmanagedReaderFactory.CreateReader<ISymUnmanagedReader3>(source, new LocalMetadataProvider());
    readerType = reader.GetType().FullName ?? "";
    Marshal.ThrowExceptionForHR(reader.GetDocuments(0, out int count, Array.Empty<ISymUnmanagedDocument>()));
    if (count is < 1 or > 16) throw new InvalidDataException("Unexpected document count");
    documentCount = count;
    var docs = new ISymUnmanagedDocument[count];
    Marshal.ThrowExceptionForHR(reader.GetDocuments(count, out int copied, docs));
    documentsCopied = copied;
    foreach (var doc in docs)
    {
        if (doc == null) continue;
        Marshal.ThrowExceptionForHR(doc.HasEmbeddedSource(out bool has));
        if (!has) continue;
        foundEmbedded = true;
        var result = doc.GetEmbeddedSource();
        sourceLength = result.Count;
        break;
    }
    if (!foundEmbedded) throw new InvalidDataException("COM reader returned no embedded-source document");
}
catch (Exception e)
{
    status = "exception";
    error = e.GetType().FullName + ": " + e.Message;
}
sw.Stop();
string[] diaModules = Array.Empty<string>();
try
{
    diaModules = Process.GetCurrentProcess().Modules.Cast<ProcessModule>()
        .Where(m => m.ModuleName.Contains("symreader", StringComparison.OrdinalIgnoreCase))
        .Select(m => m.ModuleName).Distinct().ToArray();
}
catch { }

Console.WriteLine(JsonSerializer.Serialize(new
{
    test = "windows-com-reader-embedded-source",
    status, error, readerType, declared, originalSize, embeddedBlobLength,
    documentCount, documentsCopied, foundEmbedded, sourceLength,
    pdbBytes = pdb.Length, elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
    allocatedBytes = GC.GetTotalAllocatedBytes() - before,
    framework = RuntimeInformation.FrameworkDescription,
    os = RuntimeInformation.OSDescription,
    diaModules,
    nativeAvailableInSystem32 = File.Exists(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                     "System32", "Microsoft.DiaSymReader.Native.amd64.dll"))
}));
return 0;

sealed class LocalMetadataProvider : ISymReaderMetadataProvider
{
    public unsafe bool TryGetStandaloneSignature(int token, out byte* signature, out int length)
    {
        signature = null; length = 0; return false;
    }
    public bool TryGetTypeDefinitionInfo(int token, out string namespaceName, out string typeName, out TypeAttributes attributes)
    {
        namespaceName = ""; typeName = ""; attributes = 0; return false;
    }
    public bool TryGetTypeReferenceInfo(int token, out string namespaceName, out string typeName)
    {
        namespaceName = ""; typeName = ""; return false;
    }
}
