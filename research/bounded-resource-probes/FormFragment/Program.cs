using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

const int MaxBody = 72 * 1024;
var cases = new (string Label, string Body, int Chunk, bool Cancel)[]
{
    ("plain-8k-one", "x=" + new string('A', 8192), 32768, false),
    ("plain-8k-128", "x=" + new string('A', 8192), 128, false),
    ("plain-8k-32", "x=" + new string('A', 8192), 32, false),
    ("plain-32k-512", "x=" + new string('B', 32768), 512, false),
    ("plain-32k-64", "x=" + new string('B', 32768), 64, false),
    ("percent-boundary-1", "x=hello%20world&y=%E2%82%AC&z=A%2BB", 1, false),
    ("percent-boundary-3", "x=hello%20world&y=%E2%82%AC&z=A%2BB", 3, false),
    ("multikey-8k-64", "x=" + new string('C', 8192) + "&y=end", 64, false),
    ("overcount-32", "a=1&b=2&c=3&d=4&e=5", 2, false),
    ("overvalue-512", "x=" + new string('D', 66 * 1024), 512, false),
    ("incomplete-escape-2", "x=hello%&y=%E2%82", 2, false),
    ("cancelled-read-64", "x=" + new string('E', 16384), 64, true),
};
foreach (var @case in cases)
{
    byte[] body = Encoding.UTF8.GetBytes(@case.Body);
    if (body.Length > MaxBody) throw new Exception("Self-generated body over test budget.");
    // Every test has its own Pipe; buffered data <=72 KiB. Count actual pipe read
    // notifications so a fragmented write cannot be mistaken for fragmented reads.
    var pipe = new Pipe(new PipeOptions(
        pauseWriterThreshold: 1_048_576, resumeWriterThreshold: 524_288,
        minimumSegmentSize: 64, useSynchronizationContext: false));
    var counting = new CountingReader(pipe.Reader);
    var form = new FormPipeReader(counting) {
        KeyLengthLimit = 2048, ValueLengthLimit = 64 * 1024, ValueCountLimit = 4
    };
    using var token = new CancellationTokenSource(TimeSpan.FromSeconds(6));
    var proc = Process.GetCurrentProcess();
    proc.Refresh();
    var cpuBefore = proc.TotalProcessorTime;
    long allocationBefore = GC.GetTotalAllocatedBytes();
    var sw = Stopwatch.StartNew();
    int writtenChunks = 0, fields = -1;
    string status="ok", error="", x="", y="";
    var consumer = form.ReadFormAsync(token.Token);
    try
    {
        for (int off = 0; off < body.Length; off += @case.Chunk)
        {
            if (@case.Cancel && writtenChunks == 16) token.Cancel();
            int n = Math.Min(@case.Chunk, body.Length-off);
            await pipe.Writer.WriteAsync(body.AsMemory(off, n), token.Token);
            writtenChunks++;
            // Give the consumer a chance to observe distinct PipeReader notifications.
            if (@case.Chunk < 8192) await Task.Delay(1, token.Token);
        }
        await pipe.Writer.CompleteAsync();
        var result = await consumer;
        fields = result.Count;
        x = result.TryGetValue("x", out var xv) ? xv.ToString() : "";
        y = result.TryGetValue("y", out var yv) ? yv.ToString() : "";
    }
    catch(Exception e)
    {
        status = "exception"; error = e.GetType().Name;
        try { await pipe.Writer.CompleteAsync(); } catch { }
        try { await consumer; } catch { }
    }
    finally
    {
        await pipe.Reader.CompleteAsync();
    }
    sw.Stop();
    proc.Refresh();
    Console.WriteLine(JsonSerializer.Serialize(new {
        test=@case.Label, status, error, bodyLength=body.Length, chunkBytes=@case.Chunk,
        writtenChunks, readerCalls=counting.Calls, nonemptyReads=counting.NonEmpty,
        maxBufferedBytes=counting.MaxBuffered, fields, xLength=x.Length,
        yValue=y.Length<64?y:"[long]",
        elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,2),
        cpuMs=Math.Round((proc.TotalProcessorTime-cpuBefore).TotalMilliseconds,2),
        allocatedBytes=GC.GetTotalAllocatedBytes()-allocationBefore,
        workingSetBytes=proc.WorkingSet64,
        framework=RuntimeInformation.FrameworkDescription,
        os=RuntimeInformation.OSDescription
    }));
    // Confirm post-rejection parsing still operates on fresh pipe instances.
    if (status=="exception" && !@case.Cancel && @case.Label=="plain-8k-one")
        throw new InvalidOperationException("Valid input must not be rejected");
}
return 0;

sealed class CountingReader(PipeReader inner) : PipeReader
{
    public int Calls, NonEmpty; public long MaxBuffered;
    public override void AdvanceTo(SequencePosition consumed) => inner.AdvanceTo(consumed);
    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) => inner.AdvanceTo(consumed, examined);
    public override void CancelPendingRead() => inner.CancelPendingRead();
    public override void Complete(Exception? exception=null) => inner.Complete(exception);
    public override async ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken=default)
    {
        var result = await inner.ReadAsync(cancellationToken);
        Count(result);
        return result;
    }
    public override bool TryRead(out ReadResult result)
    {
        bool ok=inner.TryRead(out result);
        if(ok)Count(result);
        return ok;
    }
    private void Count(ReadResult result)
    {
        Calls++;
        if(!result.Buffer.IsEmpty)NonEmpty++;
        MaxBuffered=Math.Max(MaxBuffered,result.Buffer.Length);
    }
}
