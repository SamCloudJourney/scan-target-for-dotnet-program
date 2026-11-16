using System.Net;
using System.Net.Http;
using System.Text.Json;

AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false });
client.Timeout = TimeSpan.FromSeconds(8);

var cases = new Dictionary<string, Result>();
foreach (var (name, path) in new[]
{
    ("encoded_slash", "/gate%2Fsecret"),
    ("canonical_path", "/gate/secret"),
    ("encoded_slash_auth", "/auth%2Fsecret")
})
{
    using var request = new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:5091" + path)
    {
        Version = HttpVersion.Version20,
        VersionPolicy = HttpVersionPolicy.RequestVersionExact
    };
    using var response = await client.SendAsync(request);
    cases[name] = new Result(path, (int)response.StatusCode, response.Version.ToString(),
        await response.Content.ReadAsStringAsync());
}
var checks = new Dictionary<string, bool>
{
    ["encoded_slash_not_route"] = cases["encoded_slash"].StatusCode == 404,
    ["canonical_route"] = cases["canonical_path"].StatusCode == 200,
    ["encoded_slash_auth_not_route"] = cases["encoded_slash_auth"].StatusCode == 404,
    ["protocol_version_two"] = cases.Values.All(x => x.HttpVersion == "2.0")
};
var obj = new { protocol = "HTTP/2", cases, checks };
var output = args.Length > 0 ? args[0] : "http2-results.json";
File.WriteAllText(output, JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true }));
Console.WriteLine(JsonSerializer.Serialize(obj));
if (!checks.Values.All(x => x)) Environment.Exit(1);

record Result(string RequestPath, int StatusCode, string HttpVersion, string Body);
