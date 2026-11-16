using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

if (args.Length != 3 ||
    args[0] is not ("shape" or "parse") ||
    !int.TryParse(args[1], out int n) || n is < 1 or > 16384 ||
    !int.TryParse(args[2], out int step) || step is < 1 or > 128)
{
    Console.Error.WriteLine("Usage: PipeShape shape|parse n[1..16384] step[1..128]");
    return 2;
}
var mode = args[0];
byte[] bytes = Encoding.UTF8.GetBytes("x=" + new string('v', n) + "&y=ok");
var pipe = new Pipe(new PipeOptions(
    pauseWriterThreshold: 65536,
    resumeWriterThreshold: 32768,
    minimumSegmentSize: 4096,
    useSynchronizationContext: false
));
var reader = new CountingPipeReader(pipe.Reader);
string status="ok", error="";
int xLen=-1;
string yVal="";
var process=Process.GetCurrentProcess();
long allocated=GC.GetTotalAllocatedBytes();
var cpu=process.TotalProcessorTime;
var sw=Stopwatch.StartNew();
int readCount=0;
using var cancel=new CancellationTokenSource(TimeSpan.FromSeconds(8));
try
{
    if (mode == "shape")
    {
        for (int offset=0;offset<bytes.Length;)
        {
            int count=Math.Min(step,bytes.Length-offset);
            bytes.AsSpan(offset,count).CopyTo(pipe.Writer.GetSpan(count));
            pipe.Writer.Advance(count);
            await pipe.Writer.FlushAsync(cancel.Token);
            var result=await reader.ReadAsync(cancel.Token);
            reader.AdvanceTo(result.Buffer.Start,result.Buffer.End);
            offset+=count;
        }
        await pipe.Writer.CompleteAsync();
        await reader.CompleteAsync();
    }
    else
    {
        var form = new FormPipeReader(reader, Encoding.UTF8)
        {
            KeyLengthLimit=2048, ValueLengthLimit=32768, ValueCountLimit=4
        };
        // Start the actual parser before providing input to its default pipe.
        var task=form.ReadFormAsync(cancel.Token);
        for(int offset=0;offset<bytes.Length;)
        {
            int count=Math.Min(step,bytes.Length-offset);
            bytes.AsSpan(offset,count).CopyTo(pipe.Writer.GetSpan(count));
            pipe.Writer.Advance(count);
            await pipe.Writer.FlushAsync(cancel.Token);
            offset+=count;
            if ((offset & 255) == 0) await Task.Yield();
        }
        await pipe.Writer.CompleteAsync();
        var parsed=await task;
        xLen=parsed.TryGetValue("x",out var x)?x.ToString().Length:-1;
        yVal=parsed.TryGetValue("y",out var y)?y.ToString():"";
        if(xLen!=n||yVal!="ok") status="output-mismatch";
        await reader.CompleteAsync();
    }
}
catch(Exception e)
{
    status="exception";
    error=e.GetType().Name+": "+e.Message;
}
sw.Stop();process.Refresh();
Console.WriteLine(JsonSerializer.Serialize(new {
    test="default-pipe-segment-geometry",
    mode,n,step,totalBytes=bytes.Length,status,error,
    xLen,yVal,readCalls=reader.ReadCalls,
    maxSegments=reader.MaxSegments,
    largestSegment=reader.LargestSegment,
    smallestNonemptySegment=reader.SmallestNonemptySegment,
    elapsedMs=Math.Round(sw.Elapsed.TotalMilliseconds,3),
    cpuMs=Math.Round((process.TotalProcessorTime-cpu).TotalMilliseconds,3),
    allocatedBytes=GC.GetTotalAllocatedBytes()-allocated,
    framework=RuntimeInformation.FrameworkDescription
}));
return 0;

sealed class CountingPipeReader(PipeReader inner) : PipeReader
{
    public int ReadCalls {get;private set;}
    public int MaxSegments {get;private set;}
    public int LargestSegment {get;private set;}
    public int SmallestNonemptySegment {get;private set;}=int.MaxValue;
    private void Measure(in ReadOnlySequence<byte> bytes)
    {
        int segments=0;
        foreach (var chunk in bytes)
        {
            if(chunk.IsEmpty)continue;
            segments++;
            LargestSegment=Math.Max(LargestSegment,chunk.Length);
            SmallestNonemptySegment=Math.Min(SmallestNonemptySegment,chunk.Length);
        }
        MaxSegments=Math.Max(MaxSegments,segments);
        ReadCalls++;
    }
    public override async ValueTask<ReadResult> ReadAsync(CancellationToken ct=default)
    {
        var r=await inner.ReadAsync(ct);
        Measure(r.Buffer);
        return r;
    }
    public override bool TryRead(out ReadResult result)
    {
        bool found=inner.TryRead(out result);
        if(found)Measure(result.Buffer);
        return found;
    }
    public override void AdvanceTo(SequencePosition consumed)=>inner.AdvanceTo(consumed);
    public override void AdvanceTo(SequencePosition consumed,SequencePosition examined)=>inner.AdvanceTo(consumed,examined);
    public override void CancelPendingRead()=>inner.CancelPendingRead();
    public override void Complete(Exception? exception=null)=>inner.Complete(exception);
    public override ValueTask CompleteAsync(Exception? exception=null)=>inner.CompleteAsync(exception);
}
