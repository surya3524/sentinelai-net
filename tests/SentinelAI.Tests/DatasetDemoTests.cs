using System.Net;
using System.Text.Json;
using Demo.Api;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.ApiFirewall;

namespace SentinelAI.Tests;

/// <summary>Sends every demo upload to the real demo API, with the firewall on and off.</summary>
public class DatasetDemoTests : IDisposable
{
    private readonly string _quarantine = Directory.CreateTempSubdirectory("sentinel-demo-q-").FullName;

    public void Dispose() => Directory.Delete(_quarantine, recursive: true);

    public static TheoryData<string> SampleIds()
    {
        var data = new TheoryData<string>();
        foreach (var s in Samples.All) data.Add(s.Id);
        return data;
    }

    private (WebApplicationFactory<Program> Factory, HttpClient Client) Start()
    {
        var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
            b.ConfigureServices(s => s.AddSingleton<IQuarantineStore>(new FileQuarantineStore(_quarantine))));
        return (factory, factory.CreateClient());
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> Upload(HttpClient client, Sample s)
    {
        var form = new MultipartFormDataContent { { new ByteArrayContent(Convert.FromBase64String(s.ContentBase64)), "config", s.FileName } };
        var response = await client.PostAsync("/datasets/imdb-reviews/config", form);
        return (response.StatusCode, JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone());
    }

    private static string[] Damage(JsonElement body) =>
        body.GetProperty("worker").EnumerateArray().Where(e => e.GetProperty("severity").GetString() == "damage")
            .Select(e => e.GetProperty("text").GetString()!).ToArray();

    [Theory]
    [MemberData(nameof(SampleIds))]
    public async Task Firewall_on_matches_the_expected_outcome(string id)
    {
        var sample = Samples.All.Single(s => s.Id == id);
        var (factory, client) = Start();
        await using var host = factory;

        var (status, body) = await Upload(client, sample);

        if (sample.Expected == "allow")
        {
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.Empty(Damage(body));
        }
        else
        {
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.False(body.TryGetProperty("worker", out _)); // the worker never saw it
        }
    }

    [Theory]
    [MemberData(nameof(SampleIds))]
    public async Task Firewall_off_shows_what_each_attack_would_do(string id)
    {
        var sample = Samples.All.Single(s => s.Id == id);
        var (factory, client) = Start();
        await using var host = factory;
        await client.PostAsync("/demo/firewall/off", null);

        var (status, body) = await Upload(client, sample);

        Assert.Equal(HttpStatusCode.OK, status);
        if (sample.Kind == "attack") Assert.NotEmpty(Damage(body));
        else Assert.Empty(Damage(body));
    }

    [Fact]
    public async Task Template_uploads_are_quarantined_for_review()
    {
        var (factory, client) = Start();
        await using var host = factory;

        var (status, body) = await Upload(client, Samples.All.Single(s => s.Id == "hf-template"));

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("Request held for review", body.GetProperty("title").GetString());
        Assert.Single(Directory.GetFiles(_quarantine, "meta.json", SearchOption.AllDirectories));
    }

    [Fact]
    public async Task Json_api_endpoint_enforces_its_schema()
    {
        var (factory, client) = Start();
        await using var host = factory;

        var ok = await client.PostAsync("/datasets/search", new StringContent("""{ "query": "reviews", "limit": 10 }""", System.Text.Encoding.UTF8, "application/json"));
        var bad = await client.PostAsync("/datasets/search", new StringContent("""{ "query": "reviews", "limit": "{{ 7 * 7 }}" }""", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }
}
