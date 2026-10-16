using System.Text.Json;
using System.Text.RegularExpressions;
using SentinelAI.Tools;

namespace Demo.Agent;

public sealed record ModelResponse(string? Text, ToolCall? ToolCall, bool Compromised);

/// <summary>
/// A deterministic stand-in for an LLM, so the demo runs offline with no API key.
///
/// It models the worst case: if an attack case's content reaches it unfiltered, it does
/// exactly what the attacker wanted (the case's CompromisedEffect). Otherwise it behaves
/// like a helpful support agent. This isolates what Sentinel itself prevents.
/// Swap in a real IChatClient later to test against an actual model.
/// </summary>
public sealed partial class SimulatedModel(FakeStore store)
{
    public ModelResponse Respond(string latestUserMessage, IReadOnlyList<KbDoc> context, CaseEffect? compromisedEffect)
    {
        if (compromisedEffect is not null)
        {
            var call = compromisedEffect.ToolCall is { } t ? new ToolCall(t.Name, t.Arguments) : null;
            return new ModelResponse(compromisedEffect.Output, call, Compromised: true);
        }

        var msg = latestUserMessage.ToLowerInvariant();
        var orderId = OrderId().Match(latestUserMessage) is { Success: true } m ? m.Value.ToUpperInvariant() : null;
        var order = orderId is null ? null : store.FindOrder(orderId);

        if (order is not null && msg.Contains("refund"))
            return Tool("IssueRefund", new() { ["orderId"] = order.Id, ["amount"] = order.Total, ["customerId"] = order.CustomerId });

        if (order is not null)
            return Tool("LookupOrder", new() { ["orderId"] = order.Id, ["customerId"] = order.CustomerId });

        if (msg.Contains("account") && (msg.Contains("close") || msg.Contains("delete") || msg.Contains("cancel")))
            return Tool("DeleteAccount", new() { ["customerId"] = FakeStore.CurrentCustomerId });

        var doc = context.FirstOrDefault(d => !d.Injected) ?? context.FirstOrDefault();
        if (doc is not null)
            return new ModelResponse($"From our {doc.Name.Replace('-', ' ')}: {doc.Content}", null, false);

        return new ModelResponse("I can help with orders, refunds, shipping and your account. What do you need?", null, false);
    }

    private static ModelResponse Tool(string name, Dictionary<string, object> args) =>
        new(null, new ToolCall(name, args.ToDictionary(a => a.Key, a => JsonSerializer.SerializeToElement(a.Value))), false);

    [GeneratedRegex(@"\bO-\d{4}\b", RegexOptions.IgnoreCase)] private static partial Regex OrderId();
}
