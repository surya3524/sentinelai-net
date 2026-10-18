using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.ApiFirewall;
using SentinelAI.Policy;

namespace SentinelAI.Tests;

public class FirewallMiddlewareTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sentinel-mw-").FullName;
    private int _handled;
    private string? _bodySeenByHandler;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private async Task<(WebApplication App, HttpClient Client)> Start(string firewallYaml = "", string mode = "enforce", Action<SentinelFirewallOptions>? options = null)
    {
        File.WriteAllText(Path.Combine(_dir, "sentinel.yaml"),
            $"mode: {mode}\napi_firewall:\n  quarantine_path: {Path.Combine(_dir, "q")}\n  endpoints:\n    - path: /datasets/*/config\n      uploads: {{ allowed_extensions: [.yaml, .json] }}\n{firewallYaml}");
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSentinelAI(o => o.Policy = PolicyLoader.FromFile(Path.Combine(_dir, "sentinel.yaml")));
        var app = builder.Build();
        app.UseSentinelFirewall(options);

        app.MapPost("/datasets/{id}/config", () => { _handled++; return Results.Ok(); });
        app.MapPost("/api/items", async (HttpRequest r) =>
        {
            _handled++;
            _bodySeenByHandler = await new StreamReader(r.Body).ReadToEndAsync();
            return Results.Ok();
        });
        app.MapPost("/api/form", () => { _handled++; return Results.Ok(); });
        app.MapGet("/api/files", () => { _handled++; return Results.Ok(); });
        app.MapPost("/health", () => { _handled++; return Results.Ok(); }).SkipSentinelFirewall();
        await app.StartAsync();
        return (app, app.GetTestClient());
    }

    private static MultipartFormDataContent Upload(string fileName, string content)
    {
        var form = new MultipartFormDataContent();
        var file = new ByteArrayContent(Encoding.UTF8.GetBytes(content));
        file.Headers.ContentType = new MediaTypeHeaderValue("application/yaml");
        form.Add(file, "config", fileName);
        form.Add(new StringContent("imdb"), "dataset");
        return form;
    }

    private static StringContent Json(string json) => new(json, Encoding.UTF8, "application/json");

    [Fact]
    public async Task Malicious_config_upload_is_stopped_before_the_endpoint_runs()
    {
        var (app, client) = await Start();
        await using var host = app;

        var response = await client.PostAsync("/datasets/imdb/config",
            Upload("config.yaml", "data_files:\n  - path: reference://spec.json\n    offset: \"{{ 7 * 7 }}\"\n"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, _handled);
        var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("Request blocked by security policy", problem.GetProperty("title").GetString());
        Assert.Equal("The request contained content that is not allowed.", problem.GetProperty("detail").GetString());
        Assert.False(problem.TryGetProperty("findings", out _)); // details hidden by default
        Assert.True(problem.TryGetProperty("traceId", out _));
    }

    [Fact]
    public async Task Clean_requests_reach_the_endpoint_with_the_body_intact()
    {
        var (app, client) = await Start();
        await using var host = app;
        const string body = """{ "name": "headphones", "price": 129.99 }""";

        var response = await client.PostAsync("/api/items", Json(body));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(body, _bodySeenByHandler);
    }

    [Fact]
    public async Task Clean_upload_passes()
    {
        var (app, client) = await Start();
        await using var host = app;
        var response = await client.PostAsync("/datasets/imdb/config", Upload("config.yaml", "data_files:\n  - path: data/train.csv\n    offset: 0\n"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, _handled);
    }

    [Fact]
    public async Task Form_fields_and_query_strings_are_inspected()
    {
        var (app, client) = await Start();
        await using var host = app;

        var form = await client.PostAsync("/api/form", new FormUrlEncodedContent([new("callback", "http://169.254.169.254/latest/")]));
        var query = await client.GetAsync("/api/files?path=../../etc/passwd");

        Assert.Equal(HttpStatusCode.BadRequest, form.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, query.StatusCode);
        Assert.Equal(0, _handled);
    }

    [Fact]
    public async Task Oversized_bodies_get_413()
    {
        var (app, client) = await Start("  max_body_bytes: 100\n");
        await using var host = app;
        var response = await client.PostAsync("/api/items", Json($$"""{ "a": "{{new string('x', 500)}}" }"""));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task Quarantine_keeps_a_copy_for_review()
    {
        var (app, client) = await Start("  detectors: { template_injection: quarantine }\n");
        await using var host = app;

        var response = await client.PostAsync("/datasets/imdb/config", Upload("config.yaml", "note: \"{{ 7 * 7 }}\"\n"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("held for review", await response.Content.ReadAsStringAsync());
        var meta = Directory.GetFiles(Path.Combine(_dir, "q"), "meta.json", SearchOption.AllDirectories);
        var saved = Assert.Single(meta);
        Assert.Contains("template_injection", File.ReadAllText(saved));
        Assert.Contains("note: \"{{ 7 * 7 }}\"", File.ReadAllText(Path.Combine(Path.GetDirectoryName(saved)!, "part0.bin")));
    }

    [Fact]
    public async Task Details_can_be_exposed_for_internal_apis()
    {
        var (app, client) = await Start("  expose_details: true\n");
        await using var host = app;
        var response = await client.PostAsync("/api/items", Json("""{ "source": "reference://x" }"""));
        var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("dangerous_url", problem.GetProperty("findings")[0].GetProperty("category").GetString());
    }

    [Fact]
    public async Task Audit_mode_lets_requests_through()
    {
        var (app, client) = await Start(mode: "audit");
        await using var host = app;
        var response = await client.PostAsync("/api/items", Json("""{ "source": "reference://x" }"""));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Endpoints_and_requests_can_opt_out()
    {
        var (app, client) = await Start(options: o => o.ShouldInspect = ctx => !ctx.Request.Headers.ContainsKey("X-Trusted-Test"));
        await using var host = app;

        var skipped = await client.PostAsync("/health", Json("""{ "source": "reference://x" }"""));
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/items") { Content = Json("""{ "source": "reference://x" }""") };
        request.Headers.Add("X-Trusted-Test", "1");
        var optedOut = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, skipped.StatusCode);
        Assert.Equal(HttpStatusCode.OK, optedOut.StatusCode);
    }

    [Fact]
    public void Missing_registration_fails_fast()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        Assert.Throws<InvalidOperationException>(() => app.UseSentinelFirewall());
    }
}
