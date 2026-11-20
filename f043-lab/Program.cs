using System.Diagnostics;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);
builder.Logging.ClearProviders();
builder.Logging.AddConsole(o => o.LogToStandardErrorThreshold = LogLevel.Warning);
builder.Logging.SetMinimumLevel(LogLevel.Debug);
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
var onDataCalls = FlowCalls();
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
        runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
        kestrelAssembly = typeof(KestrelServerOptions).Assembly.GetName().Version?.ToString(),
        onDataCalls
    });
});
app.Run();

static string[] FlowCalls()
{
    var assembly = typeof(KestrelServerOptions).Assembly;
    var type = assembly.GetType("Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http2.Http2Stream");
    var method = type?.GetMethod("OnDataAsync", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
    var bytes = method?.GetMethodBody()?.GetILAsByteArray();
    if (method == null || bytes == null) return ["method-not-found"];
    var calls = new List<string>();
    for (var i = 0; i < bytes.Length - 4; i++)
    {
        if (bytes[i] != 0x28 && bytes[i] != 0x6f) continue;
        try
        {
            var name = method.Module.ResolveMethod(BitConverter.ToInt32(bytes, i + 1))?.Name;
            if (name != null && (name.Contains("Advance") || name.Contains("OnDataRead")))
                calls.Add(i.ToString() + ":" + name);
        }
        catch { }
    }
    return calls.ToArray();
}
