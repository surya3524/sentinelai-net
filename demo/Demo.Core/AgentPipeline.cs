using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using SentinelAI;
using SentinelAI.Telemetry;
using SentinelAI.Tools;

namespace Demo.Agent;

public sealed record RunRequest(string? CaseId, string? Message, bool Protection = true, bool Pace = false);

public sealed record RunStep(string Stage, string Title, string Action, string Detail, IReadOnlyList<Finding>? Findings = null, string? RunId = null);

public sealed record PendingApproval(string Id, string RunId, string Tool, string Call, string Reason);

public sealed record RunResult(string RunId, string Reply, string Outcome, bool Protection, IReadOnlyList<RunStep> Steps, PendingApproval? Approval);

/// <summary>
/// The support agent: input → retrieval → model → tool → output. With protection on,
/// SentinelAI checks every hop; with it off, the same agent runs unguarded.
/// </summary>
public sealed partial class AgentPipeline(SentinelEngine engine, ToolGuard guard, FakeStore store, CaseCatalog catalog, IDemoEvents hub)
{
    public static readonly ActivitySource Source = new("Demo.Agent");
    private const string AgentId = "support-agent";

    private readonly SimulatedModel _model = new(store);
    private readonly ConcurrentDictionary<string, (PendingApproval Info, ToolCall Call)> _approvals = new();

    public async Task<RunResult> RunAsync(RunRequest req, CancellationToken ct = default)
    {
        var runId = Guid.NewGuid().ToString("n")[..8];
        var @case = req.CaseId is null ? null : catalog.Find(req.CaseId) ?? throw new KeyNotFoundException($"Unknown case '{req.CaseId}'");
        var turns = @case?.Turns ?? [req.Message ?? ""];
        var latest = turns[^1];
        var steps = new List<RunStep>();
        var decisions = new List<SecurityDecision>();

        using var activity = Source.StartActivity("agent.run");
        activity?.SetTag("demo.case", @case?.Id ?? "free-chat");
        activity?.SetTag("demo.protection", req.Protection);
        activity?.SetTag("enduser.id", FakeStore.CurrentUserId);

        hub.Publish("run", new { runId, title = @case?.Title ?? "Free chat", protection = req.Protection, turns });

        async Task Emit(RunStep step)
        {
            step = step with { RunId = runId };
            steps.Add(step);
            hub.Publish("step", step);
            if (req.Pace) await Task.Delay(400, ct);
        }

        RunStep FromDecision(string stage, string title, SecurityDecision d) =>
            new(stage, title, SentinelTelemetry.Format(d.PolicyAction) + (d.Enforced ? "" : " (audit)"), d.Reason,
                d.Findings.Where(f => f.Rule != "combined-score" || d.PolicyAction != SecurityAction.Allow).ToList());

        RunResult Finish(string reply, PendingApproval? approval = null)
        {
            var outcome = decisions.Count == 0 ? SecurityAction.Allow : decisions.Max(d => d.PolicyAction);
            var result = new RunResult(runId, reply, SentinelTelemetry.Format(outcome), req.Protection, steps, approval);
            activity?.SetTag("ai.security.outcome", result.Outcome);
            hub.Publish("done", new { runId, reply, outcome = result.Outcome, approval });
            hub.Publish("state", store.Snapshot());
            return result;
        }

        // 1. User input (all turns together, so payloads split across messages are seen whole).
        if (req.Protection)
        {
            var d = await engine.ScanAsync(new(ContentSource.UserInput, string.Join("\n", turns), FakeStore.CurrentUserId, AgentId,
                turns.Count > 1 ? $"conversation ({turns.Count} turns)" : "user message"), ct);
            decisions.Add(d);
            await Emit(FromDecision("input", "Scan user input", d));
            if (d.Action == SecurityAction.Block) return Finish("I can't help with that request.");
        }
        else await Emit(new("input", "User input", "unchecked", "Sentinel is off: input goes straight to the model"));

        // 2. Retrieval. A case's document is injected into the knowledge base for this run.
        var candidates = new List<KbDoc>();
        if (@case?.Document is { } injected) candidates.Add(new KbDoc(injected.Name, injected.Content, Injected: true));
        candidates.AddRange(store.Search(latest).Where(d => candidates.All(c => c.Name != d.Name)));

        var context = new List<KbDoc>();
        var injectedStopped = false;
        foreach (var doc in candidates)
        {
            if (!req.Protection)
            {
                context.Add(doc);
                await Emit(new("retrieval", $"Retrieved {doc.Name}", "unchecked", "Added to the model context without scanning"));
                continue;
            }
            var d = await engine.ScanAsync(new(ContentSource.RetrievedDocument, doc.Content, FakeStore.CurrentUserId, AgentId, doc.Name), ct);
            decisions.Add(d);
            await Emit(FromDecision("retrieval", $"Scan document {doc.Name}", d));
            if (d.Action is SecurityAction.Quarantine or SecurityAction.Block)
            {
                if (doc.Injected) injectedStopped = true;
                continue;
            }
            context.Add(doc);
        }
        if (candidates.Count == 0) await Emit(new("retrieval", "Retrieval", "none", "No knowledge-base documents matched"));

        // 3. Model. The attack's effect happens only if its content got this far.
        var effect = @case?.CompromisedEffect is { } e && !(injectedStopped && @case.Document is not null) ? e : null;
        var response = _model.Respond(latest, context, effect);
        await Emit(new("model", response.Compromised ? "Model (manipulated)" : "Model", response.Compromised ? "compromised" : "ok",
            response.ToolCall is { } tc ? $"Proposed tool call {Describe(tc)}" : "Produced a text answer"));

        // 4. Tool call.
        string? toolResult = null;
        PendingApproval? approval = null;
        if (response.ToolCall is { } call)
        {
            if (!req.Protection)
            {
                toolResult = store.Execute(call);
                await Emit(new("tool", $"Executed {call.Name}", "unchecked", toolResult));
            }
            else
            {
                var caller = new ToolCallerContext(FakeStore.CurrentUserId, FakeStore.CurrentCustomerId, AgentId, latest);
                var d = guard.Evaluate(call, caller);
                decisions.Add(d);
                await Emit(FromDecision("tool", $"Authorize {call.Name}", d));
                switch (d.Action)
                {
                    case SecurityAction.Allow:
                        toolResult = store.Execute(call);
                        await Emit(new("tool", $"Executed {call.Name}", "ok", toolResult));
                        break;
                    case SecurityAction.RequireApproval:
                        approval = new PendingApproval(Guid.NewGuid().ToString("n")[..8], runId, call.Name, Describe(call), d.Reason);
                        _approvals[approval.Id] = (approval, call);
                        hub.Publish("approval", approval);
                        break;
                }
            }
        }

        // 5. Output.
        var reply = response.Text
            ?? (toolResult is not null ? $"Done. {toolResult}"
                : approval is not null ? "This needs approval from a team member. I've sent the request."
                : response.ToolCall is not null ? "I can't do that. The action was blocked by security policy." : "");

        if (req.Protection)
        {
            var d = await engine.ScanAsync(new(ContentSource.ModelOutput, reply, FakeStore.CurrentUserId, AgentId, "assistant reply"), ct);
            decisions.Add(d);
            await Emit(FromDecision("output", "Scan model output", d));
            reply = d.Action == SecurityAction.Block ? "The response was withheld because it would have sent data to an untrusted site." : d.Content;
        }
        else
        {
            foreach (Match m in AutoLoadingUrl().Matches(reply)) store.RecordOutbound(m.Groups["url"].Value);
            await Emit(new("output", "Model output", "unchecked", "Shown to the user as-is"));
        }

        return Finish(reply, approval);
    }

    public object? ResolveApproval(string id, bool approve)
    {
        if (!_approvals.TryRemove(id, out var pending)) return null;
        using var activity = Source.StartActivity("agent.approval");
        activity?.SetTag("ai.tool.name", pending.Call.Name);
        activity?.SetTag("demo.approved", approve);

        var result = approve ? store.Execute(pending.Call) : "Rejected by reviewer. Nothing was changed.";
        var step = new RunStep("tool", approve ? $"Approved {pending.Call.Name}" : $"Rejected {pending.Call.Name}",
            approve ? "ok" : "block", result, RunId: pending.Info.RunId);
        hub.Publish("step", step);
        hub.Publish("approval_resolved", new { id, approve, result });
        hub.Publish("state", store.Snapshot());
        return new { id, approve, result };
    }

    public void ClearApprovals() => _approvals.Clear();

    private static string Describe(ToolCall c) =>
        $"{c.Name}({string.Join(", ", c.Arguments.Select(a => $"{a.Key}: {a.Value}"))})";

    [GeneratedRegex(@"(!\[[^\]]*\]\((?<url>[^)\s]+)|<img[^>]+src\s*=\s*[""'](?<url>[^""']+))", RegexOptions.IgnoreCase)]
    private static partial Regex AutoLoadingUrl();
}
