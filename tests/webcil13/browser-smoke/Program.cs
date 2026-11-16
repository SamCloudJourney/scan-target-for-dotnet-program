using System;
using System.Reflection;
using System.Runtime.InteropServices;

internal static class Program
{
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

        // Harmless rejection controls only. No relocation directory or
        // intentional memory corruption: we do NOT disclose exploit bytes
        // or claim an ASan model proves a production vulnerability.
        byte[][] rejectControls =
        {
            Array.Empty<byte>(),
            new byte[] { (byte)'W', (byte)'b', (byte)'I', (byte)'L' },
            new byte[] { (byte)'W', (byte)'b', (byte)'I', (byte)'L', 1, 0, 0, 0 },
        };
        for (var i = 0; i < rejectControls.Length; i++)
        {
            try
            {
                _ = Assembly.Load(rejectControls[i]);
                Console.Error.WriteLine($"WEBCIL13_CONTROL_{i}=UNEXPECTED_ACCEPT");
                return 3;
            }
            catch (BadImageFormatException ex)
            {
                Console.WriteLine($"WEBCIL13_CONTROL_{i}=REJECTED_{ex.GetType().Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WEBCIL13_CONTROL_{i}=OTHER_EXCEPTION_{ex.GetType().Name}");
                return 4;
            }
        }
        Console.WriteLine("WEBCIL13_RUNTIME_SMOKE_PASS=true");
        return 0;
    }
}
