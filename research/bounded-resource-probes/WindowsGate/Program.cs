using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.DiaSymReader;

if (args.Length != 1) return 2;
var pdb = File.ReadAllBytes(args[0]);
if (pdb.Length > 1_048_576 || pdb.Length < 4 || !pdb.AsSpan(0, 4).SequenceEqual("BSJB"u8))
    throw new InvalidDataException("Only the investigator-generated small Portable PDB is accepted.");

var sw = Stopwatch.StartNew();
string status = "unavailable", detail = "";
try
{
    using var source = new MemoryStream(pdb);
    // Explicit Windows native reader factory, not the PortablePdb managed SymBinder.
    var reader = SymUnmanagedReaderFactory.CreateReader<ISymUnmanagedReader3>(source, new LocalMetadataProvider());
    status = "returned";
    detail = "reader_type=" + reader.GetType().FullName;
    Marshal.ThrowExceptionForHR(reader.GetDocuments(0, out int count, Array.Empty<ISymUnmanagedDocument>()));
    detail += ";document_count=" + count;
}
catch (Exception e)
{
    status = "rejected_or_unavailable";
    detail = e.GetType().FullName + ": " + e.Message;
}
sw.Stop();
Console.WriteLine(JsonSerializer.Serialize(new
{
    test = "windows-native-reader-format-gate",
    status,
    detail,
    pdbBytes = pdb.Length,
    elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
    framework = RuntimeInformation.FrameworkDescription,
    os = RuntimeInformation.OSDescription,
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
