using System;
using System.Linq;
using System.Reflection.PortableExecutable;
using Mono.Linker;
using Mono.Linker.Steps;

namespace Research;

// Official ILLink extension point. This is a *passive* observation step:
// do not force a new symbol read, do not change the assembly, and do not
// grant any extra trust to the self-generated PE being analyzed.
public sealed class SymbolAuditStep : IStep
{
    public void Process(LinkContext context)
    {
        // Read process-wide cumulative metrics before auditing any assemblies.
        // This is an after-ingestion total, not a direct call-site allocation count.
        long cumulativeAllocatedAtStep = GC.GetTotalAllocatedBytes(false);
        long managedHeapAtStep = GC.GetGCMemoryInfo().HeapSizeBytes;
        int gc2AtStep = GC.CollectionCount(2);
        var process = System.Diagnostics.Process.GetCurrentProcess();
        process.Refresh();
        long workingSetAtStep = process.WorkingSet64;
        try
        {
            int sampleCount = 0;
            foreach (var assembly in context.GetReferencedAssemblies())
            {
                if (assembly.Name?.Name != "Sample") continue;
                sampleCount++;
                string path = context.GetAssemblyLocation(assembly);
                bool symbolsAlreadyRead = assembly.MainModule.HasSymbols;
                int declared = -1;
                try
                {
                    using var reader = new PEReader(System.IO.File.OpenRead(path));
                    var entry = reader.ReadDebugDirectory().FirstOrDefault(
                        x => x.Type == System.Reflection.PortableExecutable.DebugDirectoryEntryType.EmbeddedPortablePdb);
                    if (entry.DataSize >= 8)
                    {
                        byte[] raw = System.IO.File.ReadAllBytes(path);
                        if (entry.DataPointer > 0 && entry.DataPointer + 8 <= raw.Length)
                            declared = BitConverter.ToInt32(raw, entry.DataPointer + 4);
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("RESEARCH_LINKER_META_ERROR=" + e.GetType().Name);
                }
                Console.Error.WriteLine(
                    "RESEARCH_LINKER_AUDIT sample=Sample" +
                    " hasSymbols=" + symbolsAlreadyRead +
                    " gcCumulativeAtStep=" + cumulativeAllocatedAtStep +
                    " gcHeapAtStep=" + managedHeapAtStep +
                    " gc2AtStep=" + gc2AtStep +
                    " workingSetAtStep=" + workingSetAtStep +
                    " expected=" + (Environment.GetEnvironmentVariable("INPUT_MODE") ?? "") +
                    " path=" + path.Replace(" ","_") +
                    " sha16=" + Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(
                            System.IO.File.ReadAllBytes(path)))[..16] +
                    " declared=" + declared +
                    " moduleKind=" + assembly.MainModule.Kind +
                    " runningFramework=" + System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription);
            }
            Console.Error.WriteLine("RESEARCH_LINKER_AUDIT_END count=" + sampleCount);
        }
        catch(Exception e)
        {
            Console.Error.WriteLine("RESEARCH_LINKER_AUDIT_ERROR " + e.GetType().FullName + ": " + e.Message);
        }
    }
}
