using Demo.Agent;
using SentinelAI;
using SentinelAI.AspNetCore;
using SentinelAI.Tools;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();

builder.Services.AddSentinelAI(o => o.PolicyPath = "sentinel.yaml");
builder.Services.AddSingleton<FakeStore>();
builder.Services.AddSingleton<EventHub>();
builder.Services.AddSingleton(sp => new CaseCatalog(Path.Combine(sp.GetRequiredService<IWebHostEnvironment>().ContentRootPath, "cases")));
builder.Services.AddSingleton(sp => new AgentPipeline(
    sp.GetRequiredService<SentinelEngine>(), sp.GetRequiredService<ToolGuard>(), sp.GetRequiredService<FakeStore>(),
    sp.GetRequiredService<CaseCatalog>(), sp.GetRequiredService<EventHub>()));
builder.Services.ConfigureHttpJsonOptions(o => Json.Configure(o.SerializerOptions));

var app = builder.Build();
app.MapDefaultEndpoints();
app.UseDefaultFiles();
app.UseStaticFiles();

// The UI's app.js and app.css are shared with the WebAssembly demo and live in demo/ui
// (copied next to the app on publish).
var uiDir = new[] { Path.Combine(app.Environment.ContentRootPath, "ui"), Path.Combine(app.Environment.ContentRootPath, "..", "ui") }
    .First(Directory.Exists);
app.UseStaticFiles(new StaticFileOptions { FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(Path.GetFullPath(uiDir)) });

var api = app.MapGroup("/api");

api.MapGet("/cases", (CaseCatalog cases) => cases.Load());

api.MapPost("/run", async (RunRequest req, AgentPipeline agent, CancellationToken ct) =>
{
    if (req.CaseId is null && string.IsNullOrWhiteSpace(req.Message)) return Results.BadRequest("caseId or message is required");
    try { return Results.Ok(await agent.RunAsync(req, ct)); }
    catch (KeyNotFoundException ex) { return Results.NotFound(ex.Message); }
});

api.MapPost("/approvals/{id}/{verdict}", (string id, string verdict, AgentPipeline agent) =>
    agent.ResolveApproval(id, verdict == "approve") is { } r ? Results.Ok(r) : Results.NotFound());

api.MapGet("/state", (FakeStore store) => store.Snapshot());

api.MapPost("/reset", (FakeStore store, AgentPipeline agent, EventHub hub) =>
{
    store.Reset();
    agent.ClearApprovals();
    hub.Publish("state", store.Snapshot());
    return Results.Ok();
});

api.MapGet("/policy", (IWebHostEnvironment env) =>
    Results.Text(File.ReadAllText(Path.Combine(env.ContentRootPath, "sentinel.yaml")), "text/plain"));

// Server-sent events: every step of every run, live, to every open tab.
api.MapGet("/events", async (HttpContext ctx, EventHub hub) =>
{
    ctx.Response.Headers.ContentType = "text/event-stream";
    ctx.Response.Headers.CacheControl = "no-cache";
    var (id, reader) = hub.Subscribe();
    try
    {
        await ctx.Response.WriteAsync(": connected\n\n", ctx.RequestAborted);
        await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
        await foreach (var message in reader.ReadAllAsync(ctx.RequestAborted))
        {
            await ctx.Response.WriteAsync(message, ctx.RequestAborted);
            await ctx.Response.Body.FlushAsync(ctx.RequestAborted);
        }
    }
    catch (OperationCanceledException) { }
    finally { hub.Unsubscribe(id); }
});

app.Run();

public partial class Program;
