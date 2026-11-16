using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Rewrite;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(s =>
    s.Listen(IPAddress.Loopback, 5100, o => o.Protocols = HttpProtocols.Http1));
builder.Services.AddControllersWithViews();
builder.Services.AddAntiforgery();
builder.Services.AddResponseCaching();
builder.Services.AddOutputCache(options =>
    options.AddPolicy("public-query-all", policy => policy.SetVaryByQuery("*")
        .Expire(TimeSpan.FromMinutes(3)))
       .AddPolicy("named-query-a", policy => policy.SetVaryByQuery("a")
        .Expire(TimeSpan.FromMinutes(3))));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "impact.fixture.auth";
        o.Events.OnRedirectToLogin = c =>
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
    .AddRedirect(@"^safelegacy/(.*)$", "/local/$1", statusCode: 302));
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseResponseCaching();
app.UseOutputCache();

app.MapGet("/healthz", () => Results.Text("ready"));
app.MapGet("/cookie/issue", async (HttpContext context) =>
{
    var id = context.Request.Query["user"].ToString();
    if (id != "alice" && id != "bob") return Results.BadRequest("fixture user must be alice or bob");
    var principal = new ClaimsPrincipal(new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, id) },
        CookieAuthenticationDefaults.AuthenticationScheme));
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    return Results.Text("issued=" + id + ";pathbase=" + context.Request.PathBase);
});
app.MapGet("/cookie/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
{
    antiforgery.GetAndStoreTokens(context);
    return Results.Text("antiforgery pathbase=" + context.Request.PathBase);
});
app.MapGet("/cookie/explicit", (HttpContext context) =>
{
    // Intentionally unsafe APPLICATION-CONFIGURED path; never use in production.
    // Control: distinguish a raw CookieOptions.Path from PathBase-derived paths.
    context.Response.Cookies.Append("fixture.explicit", "no-secret",
        new CookieOptions { Path = "/;Domain=example.test", HttpOnly = true });
    return Results.Text("explicit path configured by app");
});
app.MapGet("/whoami", (HttpContext ctx) =>
    Results.Text("identity=" + ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)))
    .RequireAuthorization();

app.MapGet("/cache/public-output", (HttpContext ctx) =>
{
    var category = Lab.Category(ctx.Request.Query);
    ctx.Response.Headers["X-Lab-Variant"] = category;
    return Results.Text("PUBLIC OUTPUT;category=" + category
        + ";generation=" + Interlocked.Increment(ref Lab.PublicOutputCounter));
}).CacheOutput("public-query-all");

app.MapGet("/cache/private-output", (HttpContext ctx) =>
    Results.Text("PRIVATE FIXTURE OUTPUT;identity="
        + ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)
        + ";generation=" + Interlocked.Increment(ref Lab.PrivateOutputCounter)))
    .CacheOutput()
    .RequireAuthorization();

app.MapGet("/cache/output-cookie", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Append("fixture.issued", "no-secret");
    return Results.Text("cookie-response-gen=" + Interlocked.Increment(ref Lab.CookieCounter));
}).CacheOutput("public-query-all");


app.MapGet("/cache/format-output", (HttpContext ctx) =>
{
    // Two PUBLIC formats on the same route; query-shape collision must not
    // cause a second visitor to receive the first visitor's content type.
    var a = ctx.Request.Query.ContainsKey("a");
    ctx.Response.Headers["X-Lab-Format"] = a ? "html-A" : "json-B";
    ctx.Response.Headers["Content-Disposition"] = a
        ? "inline"
        : "attachment; filename=\"public-B.json\"";
    ctx.Response.Headers["X-Frame-Options"] = a ? "DENY" : "SAMEORIGIN";
    return Results.Content(
        a ? "<!doctype html><title>fixture-A</title><p>PUBLIC-A</p>"
          : "{\"document\":\"PUBLIC-B\"}",
        a ? "text/html" : "application/json");
}).CacheOutput("public-query-all");

app.MapGet("/cookie/reflect", (HttpContext ctx) =>
    Results.Text("cookie-header=" + ctx.Request.Headers.Cookie + ";pathbase=" + ctx.Request.PathBase));


/* Round four: conditional validators, fixed-name query vary, and client-visible
 * JSON parsing, using generated non-sensitive data only. */
app.MapGet("/fourth/output/etag", (HttpContext ctx) =>
{
    var variant = Lab.FourthVariant(ctx.Request.Query);
    ctx.Response.Headers.ETag = variant == "A" ? "\"public-A-validator\"" : "\"public-B-validator\"";
    ctx.Response.Headers["X-Lab-Variant"] = variant;
    ctx.Response.Headers["Content-Security-Policy"] = variant == "A"
        ? "default-src 'self'" : "default-src 'none'";
    return Results.Json(new {
        variant,
        generation = Interlocked.Increment(ref Lab.FourthOutputEtagCounter)
    });
}).CacheOutput("public-query-all");

app.MapGet("/fourth/output/fixed", (HttpContext ctx) =>
    Results.Text("fixed-output=" + Lab.FourthVariant(ctx.Request.Query)
        + ";generation=" + Interlocked.Increment(ref Lab.FourthOutputFixedCounter)))
    .CacheOutput("named-query-a");

app.MapGet("/fourth/output/client-json", (HttpContext ctx) =>
{
    var a = ctx.Request.Query.ContainsKey("a");
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Lab-Representation"] = a ? "html" : "json";
    return Results.Content(
        a ? "<!doctype html><title>Public A</title><p>Fixture HTML</p>"
          : "{\"variant\":\"B\",\"safe\":true}",
        a ? "text/html" : "application/json");
}).CacheOutput("public-query-all");

app.MapGet("/fourth/auth/query", (HttpContext ctx) =>
    Results.Text("private-identity=" + ctx.User.FindFirstValue(ClaimTypes.NameIdentifier)
        + ";variant=" + Lab.FourthVariant(ctx.Request.Query)
        + ";generation=" + Interlocked.Increment(ref Lab.FourthAuthCounter)))
    .CacheOutput("public-query-all")
    .RequireAuthorization();

// Protected ONLY by upstream ACL. Content is deliberately non-sensitive synthetic data.
// The ASP.NET endpoint is intentionally not authorized, to model upstream-only protection.
app.MapGet("/gate/private-document", (HttpContext ctx) =>
    Results.Text("SYNTHETIC-RESTRICTED-DOCUMENT;label=LAB-ONLY;path=" + ctx.Request.Path
        + ";raw=" + ctx.Features.Get<IHttpRequestFeature>()?.RawTarget));
app.MapGet("/gate/auth-private-document", (HttpContext ctx) =>
    Results.Text("AUTH-PROTECTED-LAB-DOCUMENT;identity="
        + ctx.User.FindFirstValue(ClaimTypes.NameIdentifier))).RequireAuthorization();

app.MapFallback((HttpContext ctx) =>
    Results.Text("NOT-ROUTED;path=" + ctx.Request.Path + ";raw="
        + ctx.Features.Get<IHttpRequestFeature>()?.RawTarget,
        "text/plain", statusCode: 404));
app.MapControllers();
app.Run();

public static class Lab
{
    public static int PublicOutputCounter;
    public static int PublicResponseCounter;
    public static int PrivateOutputCounter;
    public static int PrivateResponseCounter;
    public static int CookieCounter;
    public static int FourthOutputEtagCounter;
    public static int FourthOutputFixedCounter;
    public static int FourthResponseEtagCounter;
    public static int FourthResponseFixedCounter;
    public static int FourthAuthCounter;
    public static string FourthVariant(IQueryCollection query)
        => query.ContainsKey("a") ? "A"
        : query.ContainsKey("a=B") ? "B" : "OTHER";
    public static int FormatResponseCounter;
    public static int FormatResponseLiteCounter;

    public static string Category(IQueryCollection q)
        => q.ContainsKey("a") ? "public-A"
            : q.ContainsKey("a=B") ? "public-B"
            : "public-other";
}
[Route("cache/public-response")]
public sealed class PublicResponseController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get()
    {
        var category = Lab.Category(Request.Query);
        Response.Headers["X-Lab-Variant"] = category;
        return Content("PUBLIC RESPONSE;category=" + category
            + ";generation=" + Interlocked.Increment(ref Lab.PublicResponseCounter), "text/plain");
    }
}

[Authorize]
[Route("cache/private-response")]
public sealed class PrivateResponseController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Client)]
    public IActionResult Get()
        => Content("PRIVATE FIXTURE RESPONSE;identity="
            + User.FindFirstValue(ClaimTypes.NameIdentifier)
            + ";generation=" + Interlocked.Increment(ref Lab.PrivateResponseCounter), "text/plain");
}
[Route("cookie/tempdata")]
public sealed class TempDataController : Controller
{
    [HttpGet]
    public IActionResult Get()
    {
        TempData["fixture"] = "safe";
        return Content("tempdata pathbase=" + Request.PathBase);
    }
}

[Route("cache/format-response")]
public sealed class FormatResponseController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get()
    {
        var a = Request.Query.ContainsKey("a");
        Response.Headers["X-Lab-Format"] = a ? "html-A" : "json-B";
        Response.Headers["Content-Disposition"] = a
            ? "inline"
            : "attachment; filename=\"public-B.json\"";
        Response.Headers["X-Frame-Options"] = a ? "DENY" : "SAMEORIGIN";
        var generation = Interlocked.Increment(ref Lab.FormatResponseCounter);
        return Content(
            (a ? "<!doctype html><title>fixture-A</title><p>PUBLIC-A</p>"
               : "{\"document\":\"PUBLIC-B\"}") + ";generation=" + generation,
            a ? "text/html" : "application/json");
    }
}

[Route("cache/format-response-lite")]
public sealed class FormatResponseLiteController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get()
    {
        var a = Request.Query.ContainsKey("a");
        Response.Headers["X-Lab-Format"] = a ? "plain-A" : "json-B";
        Response.Headers["X-Lab-Download"] = a ? "view" : "json";
        var generation = Interlocked.Increment(ref Lab.FormatResponseLiteCounter);
        return Content(
            a ? "PUBLIC-A;generation=" + generation
              : "{\"document\":\"PUBLIC-B\",\"generation\":" + generation + "}",
            a ? "text/plain" : "application/json");
    }
}

[Route("fourth/response/etag")]
public sealed class FourthResponseEtagController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get()
    {
        var variant = Lab.FourthVariant(Request.Query);
        Response.Headers.ETag = variant == "A" ? "\"response-A-validator\"" : "\"response-B-validator\"";
        Response.Headers["X-Lab-Variant"] = variant;
        return Content("response-etag-variant=" + variant
            + ";generation=" + Interlocked.Increment(ref Lab.FourthResponseEtagCounter), "text/plain");
    }
}
[Route("fourth/response/fixed")]
public sealed class FourthResponseFixedController : Controller
{
    [HttpGet]
    [ResponseCache(Duration = 180, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "a" })]
    public IActionResult Get()
        => Content("fixed-response=" + Lab.FourthVariant(Request.Query)
            + ";generation=" + Interlocked.Increment(ref Lab.FourthResponseFixedCounter), "text/plain");
}
