using Demo.Agent;
using SentinelAI.Policy;
using SentinelAI.Tools;
using Xunit.Abstractions;

namespace SentinelAI.Tests;

/// <summary>
/// Runs every case in demo/Demo.Agent/cases/*.json through the real pipeline, so any case
/// file you add (for example an export from a red-team tool) is tested automatically.
/// </summary>
public class CaseTests(ITestOutputHelper output)
{
    public static TheoryData<string> CaseIds()
    {
        var data = new TheoryData<string>();
        foreach (var c in new CaseCatalog(Paths.Cases).Load()) data.Add(c.Id);
        return data;
    }

    private static (AgentPipeline Agent, FakeStore Store) Create()
    {
        var policy = PolicyLoader.FromFile(Paths.DemoPolicy);
        var store = new FakeStore();
        var agent = new AgentPipeline(SentinelEngine.CreateDefault(policy), new ToolGuard(policy), store, new CaseCatalog(Paths.Cases), new NullEvents());
        return (agent, store);
    }

    [Theory]
    [MemberData(nameof(CaseIds))]
    public async Task Protected_run_matches_expected_outcome(string caseId)
    {
        var (agent, store) = Create();
        var c = new CaseCatalog(Paths.Cases).Find(caseId)!;
        var result = await agent.RunAsync(new RunRequest(caseId, null, Protection: true));

        output.WriteLine($"{caseId}: outcome={result.Outcome}");
        foreach (var s in result.Steps) output.WriteLine($"  [{s.Stage}] {s.Title}: {s.Action} — {s.Detail}");

        if (c.Expected is not null) Assert.Equal(c.Expected, result.Outcome);
        Assert.DoesNotContain(store.Snapshot().Effects, e => e.Severity == "damage");
    }

    [Theory]
    [MemberData(nameof(CaseIds))]
    public async Task Unprotected_attacks_with_an_effect_cause_damage(string caseId)
    {
        var c = new CaseCatalog(Paths.Cases).Find(caseId)!;
        if (!c.IsAttack || c.CompromisedEffect is null) return;

        var (agent, store) = Create();
        var result = await agent.RunAsync(new RunRequest(caseId, null, Protection: false));
        var leakedInReply = c.CompromisedEffect.Output is { } o && result.Reply == o;

        // Proves each attack is real: without Sentinel it does harm or leaks data verbatim.
        Assert.True(store.Snapshot().Effects.Any(e => e.Severity == "damage") || leakedInReply,
            $"{caseId} did no harm without protection, so it doesn't demonstrate anything");
    }

    [Fact]
    public void Starter_cases_are_present()
    {
        Assert.True(new CaseCatalog(Paths.Cases).Load().Count >= 10);
    }
}

internal sealed class NullEvents : IDemoEvents
{
    public void Publish(string type, object payload) { }
}
