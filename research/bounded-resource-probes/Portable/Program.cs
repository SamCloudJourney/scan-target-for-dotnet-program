using System.Diagnostics;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.DiaSymReader;
using Microsoft.DiaSymReader.PortablePdb;

const int MaxDeclared = 8 * 1024 * 1024;
bool guarded = args.Length == 3 && args[2] == "guarded";
if ((args.Length != 2 && !guarded) || !int.TryParse(args[1], out var declared) || (declared != 0 && declared is < 1 or > MaxDeclared))
{
    Console.Error.WriteLine("Usage: PortableBridge <self-generated.pdb> <0=unaltered|256|1048576|8388608>");
    return 2;
}
byte[] pdb = File.ReadAllBytes(args[0]);
if (pdb.Length > 1024 * 1024) throw new InvalidDataException("Only a small, locally generated PDB is permitted.");
var sourceGuid = new Guid("0E8A571B-6926-466E-B4AD-8AB04611F5FE");

int offset = -1, originalDeclared = -1, blobLength = 0, documentCount = 0;
using (var stream = new MemoryStream(pdb))
using (var metadata = MetadataReaderProvider.FromPortablePdbStream(stream, MetadataStreamOptions.LeaveOpen))
{
    var md = metadata.GetMetadataReader();
    foreach (var document in md.Documents)
    {
        documentCount++;
        int token = MetadataTokens.GetToken(document);
        foreach (var infoHandle in md.GetCustomDebugInformation(MetadataTokens.EntityHandle(token)))
        {
            var info = md.GetCustomDebugInformation(infoHandle);
            if (md.GetGuid(info.Kind) != sourceGuid) continue;
            byte[] sourceBlob = md.GetBlobBytes(info.Value);
            if (sourceBlob.Length <= 8) continue;
            int candidate = pdb.AsSpan().IndexOf(sourceBlob);
            if (candidate < 0) continue;
            offset = candidate;
            blobLength = sourceBlob.Length;
            originalDeclared = BitConverter.ToInt32(sourceBlob);
            break;
        }
        if (offset >= 0) break;
    }
}
if (offset < 0) throw new InvalidDataException("EmbeddedSource custom debug info not found in self-generated PDB.");
if (declared != 0) BitConverter.GetBytes(declared).CopyTo(pdb, offset);
long before = GC.GetTotalAllocatedBytes();
string status = "ok", error = "";
int resultLength = -1, readerDocumentCount = 0;
var sw = Stopwatch.StartNew();
try
{
    if (guarded)
    {
        // Investigator-only bounded preflight. This is NOT a shipped DiaSymReader fix.
        const int MaxSource = 256 * 1024;
        int declaredNow = BitConverter.ToInt32(pdb, offset);
        if (declaredNow < 0 || declaredNow > MaxSource)
            throw new InvalidDataException("Guarded rejection: declared embedded source exceeds 256 KiB");
        if (declaredNow != 0)
        {
            using var encoded = new MemoryStream(pdb, offset + 4, blobLength - 4, false);
            using var inflater = new System.IO.Compression.DeflateStream(encoded, System.IO.Compression.CompressionMode.Decompress);
            byte[] chunk = new byte[4096];
            int total = 0, n;
            while ((n = inflater.Read(chunk)) > 0)
            {
                total = checked(total + n);
                if (total > MaxSource)
                    throw new InvalidDataException("Guarded rejection: actual source exceeds 256 KiB");
            }
            if (total != declaredNow)
                throw new InvalidDataException("Guarded rejection: declared/actual embedded source mismatch");
        }
    }
    using var stream = new MemoryStream(pdb);
    // A REAL managed Portable PDB reader; unlike the prior synthetic document,
    // this parses the PDB's metadata and exposes its ISymUnmanagedDocument.
    var importer = SymUnmanagedReaderFactory.CreateSymReaderMetadataImport(new EmptyMetadataProvider());
    var reader = new SymBinder().GetReaderFromStream(stream, importer);
    Marshal.ThrowExceptionForHR(reader.GetDocuments(0, out int count, Array.Empty<ISymUnmanagedDocument>()));
    if (count is < 1 or > 16) throw new InvalidDataException("Unexpected document count");
    var documents = new ISymUnmanagedDocument[count];
    Marshal.ThrowExceptionForHR(reader.GetDocuments(count, out int copied, documents));
    readerDocumentCount = copied;
    bool found = false;
    foreach (var doc in documents)
    {
        Marshal.ThrowExceptionForHR(doc.HasEmbeddedSource(out bool hasEmbedded));
        if (!hasEmbedded) continue;
        found = true;
        resultLength = doc.GetEmbeddedSource().Count;
        break;
    }
    if (!found) throw new InvalidDataException("No embedded source document from real PDB reader");
}
catch (Exception ex) { status = "exception"; error = ex.GetType().FullName ?? ex.GetType().Name; }
sw.Stop();
Console.WriteLine(JsonSerializer.Serialize(new
{
    test = "portable-pdb-real-reader", status, error, guarded, declared, originalDeclared,
    pdbBytes = pdb.Length, sourceBlobLength = blobLength, documentCount,
    readerDocumentCount, sourceDataOffset = offset, resultLength,
    elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
    allocatedBytes = GC.GetTotalAllocatedBytes() - before,
    workingSetBytes = Environment.WorkingSet,
    packagePair = "DiaSymReader.2.2.15+PortablePdb.1.6.0",
    framework = RuntimeInformation.FrameworkDescription
}));
return 0;

sealed class EmptyMetadataProvider : ISymReaderMetadataProvider
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
