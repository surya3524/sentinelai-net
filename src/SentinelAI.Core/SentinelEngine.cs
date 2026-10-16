using System.Text;
using SentinelAI.Policy;
using SentinelAI.Telemetry;

namespace SentinelAI;

/// <summary>
/// Runs every applicable scanner on a piece of content and turns the findings into one
/// enforced decision using <see cref="SentinelPolicy"/>.
/// </summary>
public sealed class SentinelEngine(SentinelPolicy policy, IEnumerable<IAiSecurityScanner> scanners)
{
    private readonly IReadOnlyList<IAiSecurityScanner> _scanners = scanners.ToList();

    public SentinelPolicy Policy => policy;

    /// <summary>The built-in scanners without DI. HTTP scanners from policy are not included.</summary>
    public static SentinelEngine CreateDefault(SentinelPolicy policy) => new(policy,
    [
        new Scanners.RuleScanner(policy),
        new Scanners.SecretScanner(),
        new Scanners.PiiScanner(),
        new Scanners.ExfiltrationScanner(policy),
    ]);

    public async Task<SecurityDecision> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken = default)
    {
        using var activity = SentinelTelemetry.Source.StartActivity("sentinel.scan");
        activity?.SetTag("ai.security.source", PolicyLoader.FormatSource(context.Source));
        activity?.SetTag("ai.security.source_name", context.SourceName);

        var applicable = _scanners.Where(s => s.AppliesTo(context.Source)).ToList();
        var results = await Task.WhenAll(applicable.Select(s => s.ScanAsync(context, cancellationToken)));
        var findings = results.SelectMany(r => r.Findings).ToList();

        var decision = Decide(context, findings);
        if (policy.IsAudit && decision.Action != SecurityAction.Allow)
            decision = decision with { Action = SecurityAction.Allow, Content = context.Content, Enforced = false, PolicyAction = decision.Action };

        SentinelTelemetry.Record(decision, context.UserId, context.AgentId);
        return decision;
    }

    private SecurityDecision Decide(SecurityScanContext ctx, List<Finding> findings)
    {
        var action = SecurityAction.Allow;
        var reasons = new List<string>();
        var redactions = new List<Finding>();

        // Prompt injection: compare the strongest signal (combined rule score or an external scanner) to the threshold.
        var injection = findings.Where(f => f.Category == FindingCategory.PromptInjection).ToList();
        if (injection.Count > 0)
        {
            var score = injection.Max(f => f.Confidence);
            var rule = ctx.Source == ContentSource.RetrievedDocument ? policy.PromptInjection.RetrievedDocument : policy.PromptInjection.UserInput;
            if (ctx.Source is ContentSource.UserInput or ContentSource.RetrievedDocument && score >= rule.Threshold)
            {
                action = Max(action, PolicyLoader.ParseAction(rule.Action));
                reasons.Add($"prompt injection score {score:0.00} ≥ {rule.Threshold:0.00}");
            }
        }

        Apply(FindingCategory.Secret, policy.Secrets.Action, "secret");
        Apply(FindingCategory.Pii, policy.Pii.Action, "personal data");
        Apply(FindingCategory.Exfiltration, policy.Exfiltration.Action, "data exfiltration URL");

        var content = action == SecurityAction.Redact ? Redact(ctx.Content, redactions) : ctx.Content;
        var reason = reasons.Count == 0 ? "no policy violations" : string.Join("; ", reasons);
        return new SecurityDecision(action, ctx.Source, content, findings, reason, ctx.SourceName);

        void Apply(string category, string policyAction, string label)
        {
            var hits = findings.Where(f => f.Category == category).ToList();
            if (hits.Count == 0) return;
            var a = PolicyLoader.ParseAction(policyAction);
            action = Max(action, a);
            if (a == SecurityAction.Redact) redactions.AddRange(hits.Where(h => h.Start >= 0));
            reasons.Add($"{hits.Count} {label} finding(s): {string.Join(", ", hits.Select(h => h.Rule).Distinct())}");
        }
    }

    private static SecurityAction Max(SecurityAction a, SecurityAction b) => a >= b ? a : b;

    internal static string Redact(string text, IEnumerable<Finding> spans)
    {
        // Merge overlapping spans, then replace from the end so indexes stay valid.
        var merged = new List<(int Start, int End, string Label)>();
        foreach (var f in spans.OrderBy(f => f.Start))
        {
            var end = f.Start + f.Length;
            if (merged.Count > 0 && f.Start <= merged[^1].End)
                merged[^1] = (merged[^1].Start, Math.Max(end, merged[^1].End), merged[^1].Label);
            else
                merged.Add((f.Start, end, f.Category.ToUpperInvariant()));
        }
        var sb = new StringBuilder(text);
        for (var i = merged.Count - 1; i >= 0; i--)
        {
            var (s, e, label) = merged[i];
            sb.Remove(s, e - s).Insert(s, $"[REDACTED:{label}]");
        }
        return sb.ToString();
    }
}
