using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length != 2) throw new ArgumentException("Usage: Mutate self-generated.dll output-root");
byte[] raw = File.ReadAllBytes(args[0]);
if (raw.Length > 128 * 1024) throw new InvalidDataException("Only small generated assemblies may be mutated");
using var pe = new PEReader(new MemoryStream(raw));
var entry = pe.ReadDebugDirectory().FirstOrDefault(e => e.Type == DebugDirectoryEntryType.EmbeddedPortablePdb);
if (entry.Type != DebugDirectoryEntryType.EmbeddedPortablePdb ||
    entry.DataPointer < 0 || entry.DataPointer + 8 > raw.Length)
    throw new InvalidDataException("Missing embedded PDB header");
if (!raw.AsSpan(entry.DataPointer, 4).SequenceEqual("MPDB"u8))
    throw new InvalidDataException("Bad embedded PDB signature");
int originalDeclared = BitConverter.ToInt32(raw, entry.DataPointer + 4);
byte[] altered = (byte[])raw.Clone();
byte[] small = (byte[])raw.Clone();
const int BoundedDeclared = 8 * 1024 * 1024;
const int SmallDeclared = 1 * 1024 * 1024;
BitConverter.GetBytes(BoundedDeclared).CopyTo(altered, entry.DataPointer + 4);
BitConverter.GetBytes(SmallDeclared).CopyTo(small, entry.DataPointer + 4);
foreach ((string folder, byte[] body) in new[] {
    ("InputBaseline", raw), ("InputSmall", small), ("InputAltered", altered)
})
{
    string path = Path.Combine(args[1], folder);
    Directory.CreateDirectory(path);
    File.WriteAllBytes(Path.Combine(path, "Sample.dll"), body);
}
Console.WriteLine(JsonSerializer.Serialize(new {
 test="illink-controlled-inputs", originalSize=raw.Length,
 originalDeclared, smallDeclared=SmallDeclared, alteredDeclared=BoundedDeclared,
 byteDiffCount = raw.Zip(altered, (x,y)=>x==y ? 0 : 1).Sum(),
 mode="owned_and_local"
}));
