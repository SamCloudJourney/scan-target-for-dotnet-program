using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;

public static class StartupHook
{
    private static Timer? _timer;
    private static string? _file;
    private static readonly object Locker = new();
    public static void Initialize()
    {
        string? root = Environment.GetEnvironmentVariable("RESEARCH_TRACE_ROOT");
        if (string.IsNullOrEmpty(root)) return;
        try
        {
            Directory.CreateDirectory(root);
            string test = Environment.GetEnvironmentVariable("RESEARCH_TRACE_CASE") ?? "unknown";
            var current = Process.GetCurrentProcess();
            _file = Path.Combine(root, test + "-pid" + current.Id + ".jsonl");
            Write(new { category="process_start", pid=current.Id, exe=current.ProcessName,
                cmd=Environment.CommandLine, runtime=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription });
            AppDomain.CurrentDomain.AssemblyLoad += (_, args) =>
            {
                try
                {
                    string name = args.LoadedAssembly.GetName().Name ?? "";
                    if (name.Contains("Linker", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("Cecil", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("ILLink", StringComparison.OrdinalIgnoreCase) ||
                        name.Contains("MSBuild", StringComparison.OrdinalIgnoreCase))
                        Write(new { category="assembly_loaded", name, pid=Environment.ProcessId });
                }
                catch { }
            };
            // Process-specific samples, not whole-container memory. This diagnostic
            // hook records values only; it does not patch the Microsoft linker.
            _timer = new Timer(_ =>
            {
                try {
                    current.Refresh();
                    Write(new { category="sample", pid=current.Id,
                        allocated=GC.GetTotalAllocatedBytes(false),
                        heap=GC.GetGCMemoryInfo().HeapSizeBytes,
                        workingSet=current.WorkingSet64,
                        privateBytes=current.PrivateMemorySize64,
                        cpuMs=Math.Round(current.TotalProcessorTime.TotalMilliseconds,2),
                        gc2=GC.CollectionCount(2) });
                } catch { }
            }, null, 100, 200);
            AppDomain.CurrentDomain.ProcessExit += (_, _) =>
            {
                try { _timer?.Dispose(); Write(new { category="process_exit",pid=Environment.ProcessId,allocated=GC.GetTotalAllocatedBytes(false) }); } catch {}
            };
        }
        catch { }
    }
    private static void Write(object value)
    {
        if (_file == null) return;
        try { lock(Locker) File.AppendAllText(_file, JsonSerializer.Serialize(value)+"\n"); } catch { }
    }
}
