using System;
using System.Buffers.Binary;
using System.Reflection;
using System.Runtime.InteropServices;

internal static class Program
{
    private static void Write16(byte[] data, int at, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(at), value);

    private static void Write32(byte[] data, int at, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at), value);

    // Small intentionally-invalid WebCIL image used only to investigate the
    // loader's BEFORE-VALIDATION relocation behavior on an owned runner.
    // This is not an assembly with executable managed/native code.
    private static byte[] MakeWebcilRelocationControl(uint relocationRva, ushort relocationIndex,
                                                       uint relocDirectoryLength = 32)
    {
        byte[] data = new byte[256];
        data[0] = (byte)'W'; data[1] = (byte)'b';
        data[2] = (byte)'I'; data[3] = (byte)'L';
        Write16(data, 4, 1);   // WebCIL header version 1
        Write16(data, 6, 0);
        Write16(data, 8, 1);   // one section
        Write16(data, 10, relocationIndex); // optional relocation section
        Write32(data, 28, 1);  // synthetic nonzero table-base delta
        // WebcilSectionHeader: virtualSize, virtualAddress, rawSize, rawOffset
        Write32(data, 32, relocDirectoryLength);
        Write32(data, 36, 64);
        Write32(data, 40, relocDirectoryLength);
        Write32(data, 44, 64);
        // A single relocation block (8-byte header + 2-byte fixup).
        Write32(data, 64, relocationRva);
        Write32(data, 68, 10);
        Write16(data, 72, 0x3000); // IMAGE_REL_BASED_HIGHLOW; no code
        return data;
    }

    private static int RunRelocationCase(string mode)
    {
        Console.WriteLine("WEBCIL13_MODE=" + mode);
        bool enabled = mode != "no-reloc" && mode != "invalid-index";
        ushort relocSection = mode == "invalid-index" ? (ushort)2
                            : enabled ? (ushort)1 : (ushort)0;
        uint target = mode == "inrange" ? 128u : 0x40000000u;
        uint length = mode == "short-dir" ? 4u : 32u;
        byte[] data = MakeWebcilRelocationControl(target, relocSection, length);
        // Each mode runs in a brand-new WebAssembly process. Negative controls
        // use the same huge RVA but disable relocation at header level.
        Console.WriteLine($"WEBCIL13_INPUT_HEADER=WebCILV1 size={data.Length} reloc={relocSection} target={target:x8} dirlen={length}");
        try
        {
            Console.WriteLine("WEBCIL13_BEFORE_ASSEMBLY_LOAD=true");
            _ = Assembly.Load(data);
            Console.WriteLine("WEBCIL13_OUTCOME=UNEXPECTED_ASSEMBLY_ACCEPT");
            return 5;
        }
        catch (BadImageFormatException)
        {
            Console.WriteLine("WEBCIL13_OUTCOME=REJECTED_BadImageFormatException");
            return mode == "out-of-range" ? 6 : 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("WEBCIL13_OUTCOME=OTHER_EXCEPTION_" + ex.GetType().Name);
            return 7;
        }
    }

    private static int Main()
    {
        Console.WriteLine("WEBCIL13_ACTUAL_RUNTIME_SMOKE=true");
        Console.WriteLine("WEBCIL13_FRAMEWORK=" + RuntimeInformation.FrameworkDescription);
        Console.WriteLine("WEBCIL13_OS=" + RuntimeInformation.OSDescription);
        if (!OperatingSystem.IsBrowser())
        {
            Console.Error.WriteLine("Not running inside browser-wasm.");
            return 2;
        }

        string mode = Environment.GetEnvironmentVariable("WEBCIL13_MODE") ?? "smoke";
        if (mode != "smoke")
            return RunRelocationCase(mode);

        byte[][] rejectControls =
        {
            Array.Empty<byte>(),
            new byte[] { (byte)'W', (byte)'b', (byte)'I', (byte)'L' },
            new byte[] { (byte)'W', (byte)'b', (byte)'I', (byte)'L', 1, 0, 0, 0 },
        };
        for (int i = 0; i < rejectControls.Length; i++)
        {
            try
            {
                _ = Assembly.Load(rejectControls[i]);
                Console.WriteLine($"WEBCIL13_CONTROL_{i}=UNEXPECTED_ACCEPT");
                return 3;
            }
            catch (BadImageFormatException)
            {
                Console.WriteLine($"WEBCIL13_CONTROL_{i}=REJECTED_BadImageFormatException");
            }
        }
        Console.WriteLine("WEBCIL13_RUNTIME_SMOKE_PASS=true");
        return 0;
    }
}
