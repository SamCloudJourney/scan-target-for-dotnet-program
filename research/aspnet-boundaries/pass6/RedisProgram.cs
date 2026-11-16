using Microsoft.AspNetCore.OutputCaching;
var builder = WebApplication.CreateBuilder(args);
var instance = Environment.GetEnvironmentVariable("PASS6_INSTANCE") ?? "unknown";
builder.Services.AddStackExchangeRedisOutputCache(options =>
{
    options.Configuration = "127.0.0.1:6379,abortConnect=false";
    options.InstanceName = "pass6-redis-public:";
});
builder.Services.AddOutputCache(options =>
{
    options.AddPolicy("shared", b => b.SetVaryByQuery("*")
        .Tag("pass6-public").Expire(TimeSpan.FromMinutes(5)));
});
var app = builder.Build();
app.UseOutputCache();
app.MapGet("/healthz", () => Results.Text("ready"));
app.MapGet("/redis/public", (HttpContext ctx) =>
{
    var variant = ctx.Request.Query.ContainsKey("a") ? "A"
                : ctx.Request.Query.ContainsKey("a=B") ? "B" : "other";
    ctx.Response.Headers["X-Lab-Instance"] = instance;
    ctx.Response.Headers["X-Lab-Variant"] = variant;
    return Results.Text("PUBLIC-REDIS;instance=" + instance + ";variant=" + variant);
}).CacheOutput("shared");
app.MapGet("/redis/evict", async (IOutputCacheStore store) =>
{
    await store.EvictByTagAsync("pass6-public", CancellationToken.None);
    return Results.Text("tag-invalidation-done");
});
app.Run();
