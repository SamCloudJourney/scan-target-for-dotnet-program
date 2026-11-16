using System.Net;
using System.Net.Http;
using System.Text.Json;
AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
using var client = new HttpClient(new SocketsHttpHandler
{ AllowAutoRedirect = false });
client.Timeout = TimeSpan.FromSeconds(10);
var matrix = new Dictionary<string, object>();
foreach(var (label,path) in new []{
    ("canonical", "/gate/read"),
    ("encoded_slash", "/gate%2Fread"),
    ("encoded_dot", "/public/%2e%2e/gate/read"),
    ("safe", "/healthz"),
    ("app_authorization", "/gate/auth-read")
})
{
    using var req = new HttpRequestMessage(HttpMethod.Get,"http://127.0.0.1:5201"+path)
    {Version=HttpVersion.Version20,VersionPolicy=HttpVersionPolicy.RequestVersionExact};
    using var rsp = await client.SendAsync(req);
    matrix[label] = new {target=path,status=(int)rsp.StatusCode,
        version=rsp.Version.ToString(), body=await rsp.Content.ReadAsStringAsync()};
}
var data = JsonSerializer.Serialize(new { http2=matrix },new JsonSerializerOptions {WriteIndented=true});
File.WriteAllText(args.Length>0?args[0]:"h2.json", data);
Console.WriteLine(data);
