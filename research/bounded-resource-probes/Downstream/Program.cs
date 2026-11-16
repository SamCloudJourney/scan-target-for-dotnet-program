using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.DiaSymReader;
using Mono.Cecil;

const int MaxDeclared = 8 * 1024 * 1024;
const int MaxUpload = 128 * 1024;
const string Url = "http://127.0.0.1:18765";
if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: Downstream <self-generated Sample.dll>");
    return 2;
}
byte[] sample = await File.ReadAllBytesAsync(args[0]);
if (sample.Length > MaxUpload) throw new InvalidOperationException("Only small self-generated PE input permitted.");

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = Array.Empty<string>(),
    EnvironmentName = Environments.Production,
});
builder.Logging.ClearProviders();
builder.WebHost.UseUrls(Url);
builder.WebHost.ConfigureKestrel(k => { k.Limits.MaxRequestBodySize = MaxUpload; });
builder.Services.Configure<FormOptions>(o =>
{
    o.KeyLengthLimit = 2_048;
    o.ValueLengthLimit = 64 * 1024;
    o.ValueCountLimit = 4;
});
var app = builder.Build();
int healthCount = 0;
app.MapGet("/health", () => Results.Json(new { ok = true, count = Interlocked.Increment(ref healthCount) }));

// A deliberately opt-in sample service: the REAL Mono.Cecil assembly parser is
// invoked for an uploaded, locally generated and mutated assembly. This endpoint
// is a hypothetical consumer, not proof that an in-scope Microsoft service does so.
app.MapPost("/symbols", async ctx =>
{
    bool readSymbols = ctx.Request.Query["readSymbols"].ToString() == "true";
    var start = Stopwatch.StartNew();
    long before = GC.GetTotalAllocatedBytes();
    string error = "", status = "ok";
    bool hasSymbols = false;
    try
    {
        using var incoming = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(incoming, ctx.RequestAborted);
        if (incoming.Length > MaxUpload) throw new InvalidDataException("Upload cap");
        incoming.Position = 0;
        using var module = ModuleDefinition.ReadModule(incoming, new ReaderParameters { ReadSymbols = readSymbols });
        hasSymbols = module.HasSymbols;
    }
    catch (Exception ex) { status = "exception"; error = ex.GetType().Name; }
    start.Stop();
    ctx.Response.StatusCode = status == "ok" ? 200 : 422;
    await ctx.Response.WriteAsJsonAsync(new
    {
        kind = "symbols", readSymbols, status, error, hasSymbols,
        processingMs = Math.Round(start.Elapsed.TotalMilliseconds, 3),
        allocatedBytes = GC.GetTotalAllocatedBytes() - before,
        workingSetBytes = Environment.WorkingSet
    });
});

app.MapPost("/embedded-source", async ctx =>
{
    var start = Stopwatch.StartNew();
    long before = GC.GetTotalAllocatedBytes();
    string error = "", status = "ok";
    int outputLength = -1;
    try
    {
        using var incoming = new MemoryStream();
        await ctx.Request.Body.CopyToAsync(incoming, ctx.RequestAborted);
        var blob = incoming.ToArray();
        if (blob.Length > 1024) throw new InvalidDataException("Compressed source input cap");
        if (blob.Length < 4) throw new InvalidDataException("Missing embedded-source length");
        int declared = BitConverter.ToInt32(blob);
        if (declared < 0 || declared > MaxDeclared) throw new InvalidDataException("Test budget");
        // Synthetic ISymUnmanagedDocument bypasses PDB/native reader, by design.
        // The actual Microsoft.DiaSymReader managed GetEmbeddedSource is exercised.
        outputLength = new SyntheticDocument(blob).GetEmbeddedSource().Count;
    }
    catch (Exception ex) { status = "exception"; error = ex.GetType().Name; }
    start.Stop();
    ctx.Response.StatusCode = status == "ok" ? 200 : 422;
    await ctx.Response.WriteAsJsonAsync(new
    {
        kind = "embedded-source", status, error, outputLength,
        processingMs = Math.Round(start.Elapsed.TotalMilliseconds, 3),
        allocatedBytes = GC.GetTotalAllocatedBytes() - before,
        workingSetBytes = Environment.WorkingSet
    });
});

app.MapPost("/form", async ctx =>
{
    var start = Stopwatch.StartNew();
    string status = "ok", error = "";
    int n = -1;
    try
    {
        var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
        n = form["x"].ToString().Length;
    }
    catch (Exception ex) { status = "rejected"; error = ex.GetType().Name; }
    start.Stop();
    ctx.Response.StatusCode = status == "ok" ? 200 : 400;
    await ctx.Response.WriteAsJsonAsync(new
    {
        kind = "form", status, error, valueLength = n,
        processingMs = Math.Round(start.Elapsed.TotalMilliseconds, 3)
    });
});

await app.StartAsync();
using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
{
    BaseAddress = new Uri(Url),
    Timeout = TimeSpan.FromSeconds(9)
};

try
{
    await Health("initial");
    var declaredSmall = Patch(sample, 1024);
    var declaredHuge = Patch(sample, MaxDeclared);
    var declaredMid = Patch(sample, 1024 * 1024);

    await Post("cecil-no-symbol-baseline", "/symbols?readSymbols=false", declaredSmall);
    await Post("cecil-no-symbol-huge-declaration", "/symbols?readSymbols=false", declaredHuge);
    await Post("cecil-symbol-small-declaration", "/symbols?readSymbols=true", declaredSmall);
    await Post("cecil-symbol-mid-declaration", "/symbols?readSymbols=true", declaredMid);
    await Post("cecil-symbol-huge-declaration", "/symbols?readSymbols=true", declaredHuge);

    await Post("diasym-exact-256", "/embedded-source", DocumentBlob(256));
    await Post("diasym-mismatch-1MiB", "/embedded-source", DocumentBlob(1024 * 1024));
    await Post("diasym-mismatch-8MiB", "/embedded-source", DocumentBlob(MaxDeclared));

    await Form("form-valid-16KiB", 16 * 1024, 128);
    await Form("form-valid-64KiB", 64 * 1024, 128);
    await Form("form-over-value-limit", 66 * 1024, 128);
    await Health("after-boundary-errors");

    // At most 3 controlled requests, each may declare <=8MiB (<=24MiB total).
    // The health probe checks whether unrelated work remains reachable.
    var parallel = Enumerable.Range(0, 3)
        .Select(i => Post("cecil-parallel-" + i, "/symbols?readSymbols=true", declaredHuge))
        .ToArray();
    await Task.Delay(3);
    await Health("during-three-concurrent-cecil-reads");
    await Task.WhenAll(parallel);
    await Health("final");
}
finally
{
    await app.StopAsync(TimeSpan.FromSeconds(2));
}
return 0;

async Task Health(string test)
{
    var sw = Stopwatch.StartNew();
    using var response = await http.GetAsync("/health");
    string body = await response.Content.ReadAsStringAsync();
    sw.Stop();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        test, category = "availability", statusCode = (int)response.StatusCode,
        elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
        body, framework = RuntimeInformation.FrameworkDescription
    }));
    if (!response.IsSuccessStatusCode) throw new Exception("Own loopback health failed");
}
async Task Post(string test, string path, byte[] bytes)
{
    var sw = Stopwatch.StartNew();
    using var content = new ByteArrayContent(bytes);
    using var response = await http.PostAsync(path, content);
    string body = await response.Content.ReadAsStringAsync();
    sw.Stop();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        test, category = "resource", bytesOnWire = bytes.Length,
        statusCode = (int)response.StatusCode,
        elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
        response = body, framework = RuntimeInformation.FrameworkDescription
    }));
}
async Task Form(string test, int length, int chunk)
{
    byte[] form = Encoding.ASCII.GetBytes("x=" + new string('v', length));
    var sw = Stopwatch.StartNew();
    using var content = new ChunkedFormContent(form, chunk);
    using var response = await http.PostAsync("/form", content);
    string body = await response.Content.ReadAsStringAsync();
    sw.Stop();
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        test, category = "form", bytesOnWire = form.Length, chunk,
        statusCode = (int)response.StatusCode,
        elapsedMs = Math.Round(sw.Elapsed.TotalMilliseconds, 3),
        response = body, framework = RuntimeInformation.FrameworkDescription
    }));
}
static byte[] Patch(byte[] assembly, int length)
{
    if (length is < 1 or > MaxDeclared) throw new ArgumentOutOfRangeException(nameof(length));
    byte[] bytes = (byte[])assembly.Clone();
    using var pe = new PEReader(new MemoryStream(bytes));
    var entries = pe.ReadDebugDirectory();
    var entry = entries.FirstOrDefault(x => x.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
    if (entry.Type != DebugDirectoryEntryType.EmbeddedPortablePdb || entry.DataPointer < 0)
        throw new InvalidDataException("Self-generated sample has no embedded PDB");
    int offset = checked(entry.DataPointer + 4);
    if (offset + 4 > bytes.Length) throw new InvalidDataException("Out-of-bounds debug entry");
    BitConverter.GetBytes(length).CopyTo(bytes, offset);
    return bytes;
}
static byte[] DocumentBlob(int declared)
{
    if (declared is < 1 or > MaxDeclared) throw new ArgumentOutOfRangeException(nameof(declared));
    using var output = new MemoryStream();
    output.Write(BitConverter.GetBytes(declared));
    using (var deflater = new DeflateStream(output, CompressionLevel.Optimal, leaveOpen: true))
        deflater.Write(new byte[256]);
    return output.ToArray();
}

sealed class SyntheticDocument : ISymUnmanagedDocument
{
    readonly byte[] _blob;
    public SyntheticDocument(byte[] blob) => _blob = blob;
    public int GetUrl(int n, out int count, char[] a) { count = 0; return 0; }
    public int GetDocumentType(ref Guid t) => 0;
    public int GetLanguage(ref Guid t) => 0;
    public int GetLanguageVendor(ref Guid t) => 0;
    public int GetChecksumAlgorithmId(ref Guid t) => 0;
    public int GetChecksum(int n, out int count, byte[] a) { count = 0; return 0; }
    public int FindClosestLine(int n, out int closest) { closest = n; return 0; }
    public int HasEmbeddedSource(out bool b) { b = true; return 0; }
    public int GetSourceLength(out int n) { n = _blob.Length; return 0; }
    public int GetSourceRange(int a, int b, int c, int d, int bufferLength, out int count, byte[] destination)
    {
        count = Math.Min(bufferLength, _blob.Length);
        Array.Copy(_blob, destination, count);
        return 0;
    }
}

sealed class ChunkedFormContent : HttpContent
{
    readonly byte[] _input;
    readonly int _chunkSize;
    public ChunkedFormContent(byte[] input, int chunkSize)
    {
        _input = input;
        _chunkSize = chunkSize;
        Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
    }
    protected override bool TryComputeLength(out long length) { length = _input.Length; return true; }
    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
    {
        int chunks = 0;
        for (int i = 0; i < _input.Length; i += _chunkSize)
        {
            int count = Math.Min(_chunkSize, _input.Length - i);
            await stream.WriteAsync(_input.AsMemory(i, count));
            if ((++chunks & 31) == 0) await Task.Yield();
        }
        await stream.FlushAsync();
    }
}
