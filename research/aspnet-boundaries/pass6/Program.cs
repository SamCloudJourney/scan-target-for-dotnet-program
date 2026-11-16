using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Rewrite;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(k =>
{
    k.Listen(IPAddress.Loopback, 5200, o => o.Protocols = HttpProtocols.Http1);
    k.Listen(IPAddress.Loopback, 5201, o => o.Protocols = HttpProtocols.Http2);
});
builder.Services.AddControllersWithViews();
builder.Services.AddResponseCaching();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
builder.Services.AddAntiforgery();
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("vary-all", policy => policy.SetVaryByQuery("*")
        .Expire(TimeSpan.FromMinutes(5)));
    options.AddPolicy("vary-a", policy => policy.SetVaryByQuery("a")
        .Expire(TimeSpan.FromMinutes(5)));
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "pass6.auth";
        options.Events.OnRedirectToLogin = c =>
        {
            c.Response.StatusCode = 401;
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedPrefix;
    o.KnownProxies.Clear();
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Add(IPAddress.Loopback);
    o.ForwardLimit = 1;
});
var app = builder.Build();
app.UseForwardedHeaders();
app.UseRewriter(new RewriteOptions()
    .AddRedirect(@"^legacy/(.*)$", "/$1", statusCode: 302)
    .AddRedirect(@"^safe/(.*)$", "/local/$1", statusCode: 302));
app.UseRouting();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.UseResponseCaching();
app.UseOutputCache();

app.MapGet("/healthz", () => Results.Text("ready"));
app.MapGet("/audit", () => Results.Json(new
{
    restrictedWrites = Volatile.Read(ref Lab.RestrictedWrites),
    authenticatedWrites = Volatile.Read(ref Lab.AuthenticatedWrites),
    cachePublic = Volatile.Read(ref Lab.CachePublic),
    cachePrivate = Volatile.Read(ref Lab.CachePrivate),
    cacheSlow = Volatile.Read(ref Lab.CacheSlow)
}));
app.MapGet("/raw-target", (HttpContext c) => Results.Json(new
{
    path = c.Request.Path.ToString(),
    pathBase = c.Request.PathBase.ToString(),
    raw = c.Features.Get<IHttpRequestFeature>()?.RawTarget
}));
app.MapGet("/gate/read", (HttpContext c) => Results.Json(new
{
    label = "SYNTHETIC-RESTRICTED-READ",
    path = c.Request.Path.ToString(),
    raw = c.Features.Get<IHttpRequestFeature>()?.RawTarget
}));
app.MapPost("/gate/write", (HttpContext c) => Results.Json(new
{
    label = "SYNTHETIC-RESTRICTED-WRITE",
    count = Interlocked.Increment(ref Lab.RestrictedWrites),
    path = c.Request.Path.ToString(),
    raw = c.Features.Get<IHttpRequestFeature>()?.RawTarget
}));
app.MapGet("/gate/auth-read", (HttpContext c) =>
    Results.Text("APP-AUTH-READ;identity=" + c.User.FindFirstValue(ClaimTypes.NameIdentifier)))
    .RequireAuthorization();
app.MapPost("/gate/auth-write", (HttpContext c) => Results.Json(new
{
    label = "APP-AUTH-WRITE",
    identity = c.User.FindFirstValue(ClaimTypes.NameIdentifier),
    count = Interlocked.Increment(ref Lab.AuthenticatedWrites)
})).RequireAuthorization();
app.MapGroup("/fallback").RequireAuthorization()
    .MapGet("/protected", (HttpContext c) =>
        Results.Text("FALLBACK-GROUP-IDENTITY=" + c.User.FindFirstValue(ClaimTypes.NameIdentifier)));

app.MapGet("/auth/login", async (HttpContext c) =>
{
    var id = c.Request.Query["user"].ToString();
    if (id != "alice" && id != "bob") return Results.BadRequest("fixture-only identities");
    var identity = new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, id) },
        CookieAuthenticationDefaults.AuthenticationScheme);
    await c.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));
    return Results.Text("signed-in-fixture-" + id);
});
app.MapGet("/auth/export", (HttpContext c) =>
    Results.Text("SYNTHETIC-PRIVATE-EXPORT;identity="
        + c.User.FindFirstValue(ClaimTypes.NameIdentifier)
        + ";generation=" + Interlocked.Increment(ref Lab.CachePrivate)))
    .RequireAuthorization()
    .CacheOutput("vary-all");
app.MapGet("/auth/status", (HttpContext c) =>
    Results.Text("user=" + c.User.FindFirstValue(ClaimTypes.NameIdentifier)
        + ";authenticated=" + (c.User.Identity?.IsAuthenticated ?? false)));

app.MapGet("/cache/public", (HttpContext c) =>
{
    var variant = Lab.Variant(c.Request.Query);
    c.Response.Headers["X-Lab-Variant"] = variant;
    c.Response.Headers["X-Content-Type-Options"] = "nosniff";
    c.Response.Headers["Content-Security-Policy"] =
        variant == "A" ? "default-src 'self'" : "default-src 'none'";
    c.Response.Headers["Access-Control-Allow-Origin"] =
        variant == "A" ? "http://127.0.0.1:5207" : "null";
    c.Response.Headers["ETag"] = variant == "A" ? "\"public-A\"" : "\"public-B\"";
    return Results.Content(
        variant == "A" ? "<!doctype html><title>public A</title><p>safe only</p>"
                       : "{\"variant\":\"B\",\"safe\":true}",
        variant == "A" ? "text/html" : "application/json");
}).CacheOutput("vary-all");

app.MapGet("/cache/pathbase", (HttpContext c) =>
    Results.Text("pathbase=" + c.Request.PathBase
        + ";generation=" + Interlocked.Increment(ref Lab.CachePublic)))
    .CacheOutput("vary-all");

app.MapGet("/cache/set-cookie", (HttpContext c) =>
{
    c.Response.Cookies.Append("pass6.marker", "no-secret");
    return Results.Text("generation=" + Interlocked.Increment(ref Lab.SetCookieCounter));
}).CacheOutput("vary-all");

app.MapGet("/cache/single-query", (HttpContext c) =>
    Results.Text("named-key=" + Lab.Variant(c.Request.Query)
        + ";generation=" + Interlocked.Increment(ref Lab.NamedCounter)))
    .CacheOutput("vary-a");

app.MapGet("/cache/slow", async (HttpContext c) =>
{
    var ordinal = Interlocked.Increment(ref Lab.CacheSlow);
    await Task.Delay(110);
    return Results.Text("slow-generation=" + ordinal
        + ";variant=" + Lab.Variant(c.Request.Query));
}).CacheOutput("vary-all");

app.MapGet("/cookie/antiforgery", (HttpContext c, IAntiforgery svc) =>
{
    svc.GetAndStoreTokens(c);
    return Results.Text("antiforgery;pathbase=" + c.Request.PathBase);
});
app.MapGet("/cookie/session", (HttpContext c) =>
{
    c.Session.SetString("lab", "synthetic");
    return Results.Text("session;pathbase=" + c.Request.PathBase);
});
app.MapGet("/cookie/issue", async (HttpContext c) =>
{
    var user = c.Request.Query["user"].ToString();
    if (user != "alice" && user != "bob") return Results.BadRequest();
    await c.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(new[] {
            new Claim(ClaimTypes.NameIdentifier, user)
        }, CookieAuthenticationDefaults.AuthenticationScheme)));
    return Results.Text("pathbase=" + c.Request.PathBase);
});
app.MapGet("/cookie/attributes", (HttpContext c) =>
{
    c.Response.Cookies.Append("pass6.safe", "fixture", new CookieOptions
    {
        HttpOnly = true, Secure = false, SameSite = SameSiteMode.Lax
    });
    return Results.Text("pathbase=" + c.Request.PathBase);
});

app.MapFallback((HttpContext c) => Results.Text(
    "NO-ROUTE;path=" + c.Request.Path
        + ";raw=" + c.Features.Get<IHttpRequestFeature>()?.RawTarget,
    "text/plain", statusCode: 404));
app.MapControllers();
app.Run();

public static class Lab
{
    public static int RestrictedWrites;
    public static int AuthenticatedWrites;
    public static int CachePublic;
    public static int CachePrivate;
    public static int CacheSlow;
    public static int SetCookieCounter;
    public static int NamedCounter;
    public static int ResponseCorsCounter;
    public static int ResponseCounter;
    public static int ResponsePrivateCounter;
    public static string Variant(IQueryCollection query)
        => query.ContainsKey("a") ? "A"
           : query.ContainsKey("a=B") ? "B"
           : "OTHER";
}

[Route("cache/response")]
public class PublicResponseController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 240, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] {"*"})]
    public IActionResult Get()
    {
        var variant = Lab.Variant(Request.Query);
        Response.Headers["X-Lab-Variant"] = variant;
        Response.Headers.ETag = variant == "A" ? "\"resp-A\"" : "\"resp-B\"";
        return Content("PUBLIC-RESPONSE;variant=" + variant
            + ";generation=" + Interlocked.Increment(ref Lab.ResponseCounter), "text/plain");
    }
}

[Microsoft.AspNetCore.Authorization.Authorize]
[Route("cache/response-private")]
public class PrivateResponseController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 240, Location = ResponseCacheLocation.Client)]
    public IActionResult Get() => Content(
        "PRIVATE-RESPONSE;identity=" + User.FindFirstValue(ClaimTypes.NameIdentifier)
            + ";generation=" + Interlocked.Increment(ref Lab.ResponsePrivateCounter), "text/plain");
}

[Route("cookie/tempdata")]
public class CookieTempDataController : Controller
{
    [HttpGet]
    public IActionResult Get()
    {
        TempData["fixture"] = "safe";
        return Content("tempdata;pathbase=" + Request.PathBase);
    }
}

// Separately cacheable MVC ResponseCaching CORS policy test. PUBLIC data only.
[Route("cache/response-cors")]
public class ResponseCorsFixtureController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 240, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get()
    {
        var variant = Lab.Variant(Request.Query);
        Response.Headers["Access-Control-Allow-Origin"] =
            variant == "A" ? "http://127.0.0.1:5207" : "null";
        Response.Headers["X-Lab-Cors-Variant"] = variant;
        return Content("PUBLIC-RESPONSE-CORS;variant=" + variant
            + ";generation=" + Interlocked.Increment(ref Lab.ResponseCorsCounter), "text/plain");
    }
}
