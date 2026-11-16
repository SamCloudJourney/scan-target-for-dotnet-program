using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Yarp.ReverseProxy.Configuration;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 5206,
    options => options.Protocols = HttpProtocols.Http1AndHttp2));
builder.Services.AddReverseProxy().LoadFromMemory(
    new[] { new RouteConfig
    {
        RouteId = "local-only",
        ClusterId = "backend",
        Match = new RouteMatch { Path = "{**catch-all}" }
    }},
    new[] { new ClusterConfig
    {
        ClusterId = "backend",
        Destinations = new Dictionary<string, DestinationConfig> {
            ["local"] = new() { Address = "http://127.0.0.1:5200/" }
        }
    }});
var app = builder.Build();
// The same simple path-prefix authorization boundary, now inside the
// Microsoft-owned ASP.NET proxy middleware pipeline. Synthetic data only.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/gate", StringComparison.OrdinalIgnoreCase))
    {
        ctx.Response.StatusCode = 403;
        await ctx.Response.WriteAsync("YARP-SYNTHETIC-DENY");
        return;
    }
    await next();
});
app.MapReverseProxy();
app.Run();
