using System.Diagnostics;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Warning);
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(50743, listen => listen.Protocols = HttpProtocols.Http2);
    if (Environment.GetEnvironmentVariable("F043_TIGHT") == "1")
    {
        options.Limits.Http2.InitialConnectionWindowSize = 65_535;
        options.Limits.Http2.InitialStreamWindowSize = 65_535;
        options.Limits.Http2.MaxStreamsPerConnection = 4;
    }
});
var app = builder.Build();
var started = 0;
app.MapPost("/hold", async (HttpContext context) =>
{
    Interlocked.Increment(ref started);
    try { await Task.Delay(TimeSpan.FromSeconds(40), context.RequestAborted); }
    catch (OperationCanceledException) { }
});
app.MapGet("/health", () =>
{
    var p = Process.GetCurrentProcess();
    return Results.Json(new
    {
        ok = true,
        started = Volatile.Read(ref started),
        workingSet = p.WorkingSet64,
        managed = GC.GetTotalMemory(false),
        threads = p.Threads.Count,
        cpuMs = p.TotalProcessorTime.TotalMilliseconds,
        runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription
    });
});
app.Run();
