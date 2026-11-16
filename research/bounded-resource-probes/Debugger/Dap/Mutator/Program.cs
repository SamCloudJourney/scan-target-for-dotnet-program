using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text.Json;
if(args.Length!=3)throw new ArgumentException("Usage: PdbMutator <generated.pdb> <target-root> <declared>");
int declared=int.Parse(args[2]);
if(declared<1 || declared>8*1024*1024)throw new InvalidDataException("Only up to 8 MiB declared source is allowed");
byte[] raw=File.ReadAllBytes(args[0]);
if(raw.Length>1024*1024)throw new InvalidDataException("Only investigator-generated Portable PDB");
var guid=new Guid("0E8A571B-6926-466E-B4AD-8AB04611F5FE");
int offset=-1, originalSize=-1;
using(var stream=new MemoryStream(raw))
using(var provider=MetadataReaderProvider.FromPortablePdbStream(stream,MetadataStreamOptions.LeaveOpen))
{
 var md=provider.GetMetadataReader();
 foreach(var document in md.Documents)
 {
  foreach(var handle in md.GetCustomDebugInformation(MetadataTokens.EntityHandle(MetadataTokens.GetToken(document))))
  {
   var info=md.GetCustomDebugInformation(handle);
   if(md.GetGuid(info.Kind)!=guid)continue;
   var bytes=md.GetBlobBytes(info.Value);
   if(bytes.Length<8)continue;
   offset=raw.AsSpan().IndexOf(bytes);
   originalSize=BitConverter.ToInt32(bytes,0);
   if(offset>=0)break;
  }
  if(offset>=0)break;
 }
}
if(offset<0)throw new InvalidDataException("EmbeddedSource metadata not found");
var mutated=(byte[])raw.Clone();
BitConverter.GetBytes(declared).CopyTo(mutated,offset);
Directory.CreateDirectory(args[1]);
File.WriteAllBytes(Path.Combine(args[1],"Debuggee.pdb"),mutated);
Console.WriteLine(JsonSerializer.Serialize(new { test="debugger-pdb-mutation",offset,pdbBytes=raw.Length,
 originalSize,declared,changedBytes=raw.Zip(mutated,(a,b)=>a==b?0:1).Sum()}));
