using System.Globalization;
using System.Text.Json;
using SentinelAI.Policy;
using SentinelAI.Telemetry;

namespace SentinelAI.Tools;

public sealed record ToolCall(string Name, IReadOnlyDictionary<string, JsonElement> Arguments)
{
    public string? GetString(string arg) =>
        Arguments.TryGetValue(arg, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText() : null;

    public decimal? GetDecimal(string arg)
    {
        if (!Arguments.TryGetValue(arg, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetDecimal(out var d)) return d;
        return decimal.TryParse(v.ToString(), NumberStyles.Number, CultureInfo.InvariantCulture, out var p) ? p : null;
    }
}

/// <summary>
/// Who is acting. Supplied by your app from its authenticated session, never by the model.
/// <paramref name="OwnerId"/> is the id that a tool's <c>ownership_arg</c> must equal
/// (a customer, tenant or account id).
/// </summary>
public sealed record ToolCallerContext(string UserId, string? OwnerId, string? AgentId, string LatestUserMessage);

/// <summary>
/// Deterministic authorization for agent tool calls. Runs after the model proposes a call
/// and before your code executes it, so a fooled model still cannot act beyond policy.
/// </summary>
public sealed class ToolGuard(SentinelPolicy policy)
{
    public SecurityDecision Evaluate(ToolCall call, ToolCallerContext caller)
    {
        using var activity = SentinelTelemetry.Source.StartActivity("sentinel.tool_guard");
        activity?.SetTag("ai.tool.name", call.Name);

        var decision = EvaluateCore(call, caller);
        if (policy.IsAudit && decision.Action != SecurityAction.Allow)
            decision = decision with { Action = SecurityAction.Allow, Enforced = false, PolicyAction = decision.Action };

        SentinelTelemetry.Record(decision, caller.UserId, caller.AgentId);
        return decision;
    }

    private SecurityDecision EvaluateCore(ToolCall call, ToolCallerContext caller)
    {
        var content = $"{call.Name}({string.Join(", ", call.Arguments.Select(a => $"{a.Key}: {a.Value}"))})";
        SecurityDecision Decide(SecurityAction action, string rule, string reason) =>
            new(action, ContentSource.ToolCall, content,
                [new Finding("tool_guard", FindingCategory.ToolPolicy, rule, 1.0, Detail: reason)], reason, call.Name);

        if (!policy.Tools.TryGetValue(call.Name, out var tool))
            return Decide(SecurityAction.Block, "unknown-tool", $"'{call.Name}' is not in the tool policy (default deny)");

        var configured = PolicyLoader.ParseAction(tool.Action);
        if (configured == SecurityAction.Block)
            return Decide(SecurityAction.Block, "tool-disabled", $"'{call.Name}' is disabled by policy");

        if (tool.OwnershipArg is { } ownerArg)
        {
            var target = call.GetString(ownerArg);
            if (caller.OwnerId is null || !string.Equals(target, caller.OwnerId, StringComparison.OrdinalIgnoreCase))
                return Decide(SecurityAction.Block, "ownership",
                    $"{ownerArg}={target ?? "(missing)"} does not belong to caller {caller.UserId} ({caller.OwnerId ?? "no owner id"})");
        }

        if (tool.RequireUserIntent.Count > 0 &&
            !tool.RequireUserIntent.Any(k => caller.LatestUserMessage.Contains(k, StringComparison.OrdinalIgnoreCase)))
            return Decide(SecurityAction.Block, "ungrounded",
                $"user never asked for '{call.Name}' (needs one of: {string.Join(", ", tool.RequireUserIntent)})");

        if (tool.DestinationArg is { } destArg)
        {
            var dest = call.GetString(destArg) ?? "";
            if (!DestinationAllowed(dest, tool.AllowedDestinations))
                return Decide(SecurityAction.Block, "destination", $"{destArg}={dest} is not an allowed destination");
        }

        if (tool.AmountArg is { } amountArg)
        {
            var amount = call.GetDecimal(amountArg);
            if (amount is null || amount < 0)
                return Decide(SecurityAction.Block, "amount-invalid", $"{amountArg} is missing or negative");
            if (tool.MaxAmount is { } max && amount > max)
                return Decide(SecurityAction.Block, "amount-limit", $"{amountArg}={amount} exceeds hard limit {max}");
            if (tool.ApprovalAbove is { } above && amount > above)
                return Decide(SecurityAction.RequireApproval, "amount-approval", $"{amountArg}={amount} is above {above}; a human must approve");
        }

        if (configured == SecurityAction.RequireApproval)
            return Decide(SecurityAction.RequireApproval, "approval-required", $"'{call.Name}' is {tool.Risk} risk and always needs approval");

        return new SecurityDecision(SecurityAction.Allow, ContentSource.ToolCall, content, [], "within policy", call.Name);
    }

    private static bool DestinationAllowed(string dest, List<string> allowed)
    {
        string host;
        if (dest.Contains('@')) host = dest[(dest.LastIndexOf('@') + 1)..];
        else if (Uri.TryCreate(dest, UriKind.Absolute, out var u)) host = u.Host;
        else return false;
        host = host.Trim().ToLowerInvariant();
        return allowed.Any(d => host == d.ToLowerInvariant() || host.EndsWith("." + d.ToLowerInvariant(), StringComparison.Ordinal));
    }
}
