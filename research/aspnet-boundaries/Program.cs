using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddResponseCaching();
builder.Services.AddOutputCache(options =>
    options.AddPolicy("all-query", policy => policy
        .SetVaryByQuery("*")
        .Expire(TimeSpan.FromMinutes(10))));
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "lab.auth";
        options.LoginPath = "/login";
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedPrefix;
    options.KnownProxies.Add(IPAddress.Loopback);
    options.ForwardLimit = 1;
});

var app = builder.Build();
app.UseForwardedHeaders();
app.UseRewriter(new RewriteOptions().AddRedirect(@"^legacy/(.*)$", "/$1", statusCode: 302));
app.UseRouting();
app.UseResponseCaching();
app.UseOutputCache();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => "ready");
app.MapGet("/cookie", async (HttpContext context) =>
{
    var identity = new ClaimsIdentity(
        new[] { new Claim(ClaimTypes.NameIdentifier, "fixture-user") },
        CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));
    await context.Response.WriteAsync("pathbase=" + context.Request.PathBase);
});

app.MapGet("/output", (HttpContext context) =>
    Results.Text(
        "output-id=" + Interlocked.Increment(ref Lab.OutputCounter)
        + ";shape=" + Lab.Shape(context.Request.Query),
        "text/plain")).CacheOutput("all-query");

app.MapGet("/output-cookie", (HttpContext context) =>
{
    context.Response.Cookies.Append("fixture", "local-test-only");
    return Results.Text("output-cookie-id=" + Interlocked.Increment(ref Lab.OutputCookieCounter));
}).CacheOutput("all-query");

app.MapGet("/gate/secret", (HttpContext context) =>
    Results.Text("UPSTREAM-GATED;path=" + context.Request.Path
        + ";raw=" + context.Features.Get<IHttpRequestFeature>()?.RawTarget));
app.MapGet("/auth/secret", (HttpContext context) =>
    Results.Text("APP-AUTH-GATED;path=" + context.Request.Path)).RequireAuthorization();

app.MapFallback((HttpContext context) =>
    Results.Text("NOT-ROUTED;path=" + context.Request.Path
        + ";raw=" + context.Features.Get<IHttpRequestFeature>()?.RawTarget,
        "text/plain", statusCode: 404));

app.MapControllers();
app.Run("http://127.0.0.1:5089");

public static class Lab
{
    public static int OutputCounter;
    public static int OutputCookieCounter;
    public static int ResponseCounter;
    public static string Shape(IQueryCollection query)
        => string.Join("|", query.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => p.Key.Length + ":" + p.Key + "="
                + p.Value.ToString().Length + ":" + p.Value));
}

[ApiController]
[Route("response")]
public class ResponseFixtureController : ControllerBase
{
    [HttpGet]
    [ResponseCache(Duration = 600, Location = ResponseCacheLocation.Any, VaryByQueryKeys = new[] { "*" })]
    public IActionResult Get() => Content(
        "response-id=" + Interlocked.Increment(ref Lab.ResponseCounter)
        + ";shape=" + Lab.Shape(Request.Query),
        "text/plain");
}
