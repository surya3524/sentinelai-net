using System.Diagnostics;
using System.Diagnostics.Metrics;
using SentinelAI.Policy;

namespace SentinelAI.Telemetry;

/// <summary>
/// OpenTelemetry instrumentation. Register the source and meter named <see cref="Name"/>
/// with your tracer/meter providers; decisions then appear on the request's own trace.
/// </summary>
public static class SentinelTelemetry
{
    public const string Name = "SentinelAI";

    public static readonly ActivitySource Source = new(Name, "0.1.0");
    private static readonly Meter Meter = new(Name, "0.1.0");
    private static readonly Counter<long> Decisions = Meter.CreateCounter<long>("sentinel.decisions", description: "Security decisions by action and source");
    private static readonly Counter<long> Findings = Meter.CreateCounter<long>("sentinel.findings", description: "Scanner findings by category");

    /// <summary>Raised for every decision; the demo streams these to the browser.</summary>
    public static event Action<SecurityDecision>? DecisionRecorded;

    public static void Record(SecurityDecision d, string? userId, string? agentId)
    {
        var action = Format(d.Action);
        var source = PolicyLoader.FormatSource(d.Source);
        var top = d.Findings.OrderByDescending(f => f.Confidence).FirstOrDefault();

        var tags = new ActivityTagsCollection
        {
            ["ai.security.action"] = action,
            ["ai.security.policy_action"] = Format(d.PolicyAction),
            ["ai.security.enforced"] = d.Enforced,
            ["ai.security.source"] = source,
            ["ai.security.source_name"] = d.SourceName,
            ["ai.security.reason"] = d.Reason,
            ["ai.security.findings"] = d.Findings.Count,
            ["ai.security.top_rule"] = top?.Rule,
            ["ai.security.top_scanner"] = top?.Scanner,
            ["ai.security.confidence"] = top?.Confidence,
            ["enduser.id"] = userId,
            ["ai.agent.id"] = agentId,
        };
        var current = Activity.Current;
        current?.AddEvent(new ActivityEvent("ai.security.decision", tags: tags));
        if (d.PolicyAction >= SecurityAction.Quarantine) current?.SetStatus(ActivityStatusCode.Error, d.Reason);

        Decisions.Add(1, new("action", action), new("source", source), new("enforced", d.Enforced));
        foreach (var f in d.Findings)
            Findings.Add(1, new("category", f.Category), new("scanner", f.Scanner));

        DecisionRecorded?.Invoke(d);
    }

    public static string Format(SecurityAction a) => a switch
    {
        SecurityAction.RequireApproval => "require_approval",
        _ => a.ToString().ToLowerInvariant(),
    };
}
