using Demo.Api;
using SentinelAI.ApiFirewall;

var builder = WebApplication.CreateBuilder(args);
builder.AddServiceDefaults();
builder.Services.AddSentinelAI();   // reads sentinel.yaml, including the api_firewall section

var firewallOn = true;              // flipped from the demo UI

var app = builder.Build();
app.MapDefaultEndpoints();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseSentinelFirewall(o => o.ShouldInspect = _ => firewallOn);

// The API being protected: a dataset hub that accepts config uploads for background processing.
app.MapPost("/datasets/{id}/config", async (string id, IFormFile config) =>
{
    using var buffer = new MemoryStream();
    await config.CopyToAsync(buffer);
    var effects = SimulatedWorker.Process(config.FileName, buffer.ToArray());
    return Results.Ok(new { dataset = id, file = config.FileName, accepted = true, worker = effects });
}).DisableAntiforgery();

app.MapPost("/datasets/search", (SearchRequest req) =>
    Results.Ok(new { req.Query, results = Array.Empty<string>() }));

// Demo controls, outside the firewall.
var demo = app.MapGroup("/demo").SkipSentinelFirewall();
demo.MapGet("/samples", () => Samples.All);
demo.MapGet("/state", () => new { firewall = firewallOn });
demo.MapPost("/firewall/{state}", (string state) =>
{
    firewallOn = state == "on";
    return new { firewall = firewallOn };
});
demo.MapGet("/policy", (IWebHostEnvironment env) => Results.Text(File.ReadAllText(Path.Combine(env.ContentRootPath, "sentinel.yaml")), "text/plain"));

app.Run();

public sealed record SearchRequest(string Query, int? Limit);

public partial class Program;
