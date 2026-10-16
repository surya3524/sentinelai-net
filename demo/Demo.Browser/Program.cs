using System.Reflection;
using Demo.Agent;
using Demo.Browser;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SentinelAI;
using SentinelAI.Policy;
using SentinelAI.Tools;

// The whole demo — SentinelAI, the support agent and its fake data — runs in the browser.
// Each visitor gets their own copy, so one person's actions never affect another's.
var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<Bridge>("#blazor-root");

var assembly = Assembly.GetExecutingAssembly();
string Resource(string name)
{
    using var stream = assembly.GetManifestResourceStream(name) ?? throw new InvalidOperationException($"Missing resource {name}");
    return new StreamReader(stream).ReadToEnd();
}

var policyYaml = Resource("sentinel.yaml");
var policy = PolicyLoader.FromYaml(policyYaml);
var caseFiles = assembly.GetManifestResourceNames().Where(n => n.StartsWith("cases/")).Order().Select(Resource).ToList();

builder.Services.AddSingleton(new PolicyText(policyYaml));
builder.Services.AddSingleton(policy);
builder.Services.AddSingleton<FakeStore>();
builder.Services.AddSingleton<BrowserEvents>();
builder.Services.AddSingleton(sp => new AgentPipeline(
    SentinelEngine.CreateDefault(policy), new ToolGuard(policy), sp.GetRequiredService<FakeStore>(),
    new CaseCatalog(() => caseFiles), sp.GetRequiredService<BrowserEvents>()));
builder.Services.AddSingleton(new CaseCatalog(() => caseFiles));

await builder.Build().RunAsync();

namespace Demo.Browser
{
    public sealed record PolicyText(string Yaml);
}
