using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

if (args.Length != 3 || !int.TryParse(args[1], out int n) ||
    !int.TryParse(args[2], out int step) ||
    n is < 1 or > 8192 || step is < 1 or > 256 ||
    args[0] is not ("utf8-segmented" or "utf16-segmented" or "utf16be-segmented" or "utf8-contiguous" or
                    "readeronly-utf8-segmented" or "readeronly-utf16-segmented"))
{
    Console.Error.WriteLine("Usage: FormMatrix utf8-segmented|utf16-segmented|utf16be-segmented|utf8-contiguous N[1..8192] STEP[1..256]");
    return 2;
}
bool readerOnly = args[0].StartsWith("readeronly-", StringComparison.Ordinal);
var kind = readerOnly ? args[0]["readeronly-".Length..] : args[0];
Encoding encoding = kind.StartsWith("utf16be", StringComparison.Ordinal)
    ? Encoding.BigEndianUnicode
    : kind.StartsWith("utf16", StringComparison.Ordinal) ? Encoding.Unicode : Encoding.UTF8;
string body = "x=" + new string('v', n) + "&y=ok";
byte[] bytes = encoding.GetBytes(body);
var reader = new FragmentsReader(bytes, kind.EndsWith("segmented", StringComparison.Ordinal) ? 13 : bytes.Length, step);
var parser = new FormPipeReader(reader, encoding)
{
    KeyLengthLimit = 2048,
    ValueLengthLimit = 32768,
    ValueCountLimit = 4
};
string resultStatus = "ok", error = "";
int xLen = -1;
string yValue = "";
var proc = Process.GetCurrentProcess();
long allocationBefore = GC.GetTotalAllocatedBytes();
var cpu = proc.TotalProcessorTime;
var timer = Stopwatch.StartNew();
try
{
    using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(6));
    if (readerOnly)
    {
        while (true)
        {
            var chunk = await reader.ReadAsync(cancel.Token);
            reader.AdvanceTo(chunk.Buffer.Start, chunk.Buffer.End);
            if (chunk.IsCompleted) break;
        }
        resultStatus = "reader-only";
    }
    else
    {
        var form = await parser.ReadFormAsync(cancel.Token);
        xLen = form.TryGetValue("x", out var parsedX) ? parsedX.ToString().Length : -1;
        yValue = form.TryGetValue("y", out var parsedY) ? parsedY.ToString() : "";
        if (xLen != n || yValue != "ok")
            resultStatus = "output-mismatch";
    }
}
catch (Exception ex) { resultStatus = "exception"; error = ex.GetType().Name + ": " + ex.Message; }
timer.Stop(); proc.Refresh();
Console.WriteLine(JsonSerializer.Serialize(new
{
    test = "bounded-form-pipe-segment-encoding-matrix",
    kind, n, step, readerOnly, precomputedPositions = true, bytes = bytes.Length, readerCalls = reader.ReadCalls,
    status = resultStatus, error, xLen, yValue,
    elapsedMs = Math.Round(timer.Elapsed.TotalMilliseconds, 3),
    cpuMs = Math.Round((proc.TotalProcessorTime - cpu).TotalMilliseconds, 3),
    allocatedBytes = GC.GetTotalAllocatedBytes() - allocationBefore,
    framework = RuntimeInformation.FrameworkDescription
}));
return 0;

sealed class Segment : ReadOnlySequenceSegment<byte>
{
    public Segment(ReadOnlyMemory<byte> data) => Memory = data;
    public Segment Add(ReadOnlyMemory<byte> data)
    {
        var next = new Segment(data) { RunningIndex = RunningIndex + Memory.Length };
        Next = next;
        return next;
    }
}

// All segments are constructed once; the Reader exposes progressively longer
// prefixes without rebuilding the segmented sequence on every read.
sealed class FragmentsReader : PipeReader
{
    private readonly ReadOnlySequence<byte> _all;
    private readonly int _step;
    private readonly int _length;
    private readonly SequencePosition[] _positions;
    private int _visible;
    private SequencePosition _consumed;
    public int ReadCalls { get; private set; }

    public FragmentsReader(byte[] data, int segmentSize, int step)
    {
        _length = data.Length;
        _step = step;
        _positions = new SequencePosition[data.Length + 1];
        var first = new Segment(data.AsMemory(0, Math.Min(segmentSize, data.Length)));
        var last = first;
        for (int i = 0; i < first.Memory.Length; i++)
            _positions[i] = new SequencePosition(first, i);
        for (int offset = first.Memory.Length; offset < data.Length;)
        {
            int size = Math.Min(segmentSize, data.Length - offset);
            last = last.Add(data.AsMemory(offset, size));
            for (int i = 0; i < size; i++)
                _positions[offset + i] = new SequencePosition(last, i);
            offset += size;
        }
        _positions[data.Length] = new SequencePosition(last, last.Memory.Length);
        _all = new ReadOnlySequence<byte>(first, 0, last, last.Memory.Length);
        _consumed = _all.Start;
    }

    public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _visible = Math.Min(_length, _visible + _step);
        ReadCalls++;
        var end = _positions[_visible];
        var visibleSlice = _all.Slice(_consumed, end);
        return ValueTask.FromResult(new ReadResult(visibleSlice, false, _visible >= _length));
    }

    public override bool TryRead(out ReadResult result) { result = default; return false; }
    public override void AdvanceTo(SequencePosition consumed) => _consumed = consumed;
    public override void AdvanceTo(SequencePosition consumed, SequencePosition examined) => _consumed = consumed;
    public override void CancelPendingRead() { }
    public override void Complete(Exception? exception = null) { }
}
