using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.AI;
using SentinelAI.Telemetry;
using SentinelAI.Tools;

namespace SentinelAI.Extensions.AI;

public sealed class SentinelChatClientOptions
{
    /// <summary>Name of the agent, recorded on security events. Overridden by the caller's AgentId.</summary>
    public string? AgentId { get; set; }

    /// <summary>How many recent user messages are scanned together, so payloads split across turns are seen whole.</summary>
    public int UserTurnsToScan { get; set; } = 3;

    /// <summary>Scan what tools return for injected instructions before the model reads it.</summary>
    public bool ScanToolResults { get; set; } = true;

    /// <summary>Reply sent when user input is blocked. The model is not called.</summary>
    public string BlockedInputMessage { get; set; } = "I can't help with that request.";

    /// <summary>Reply sent in place of a model response that policy blocks.</summary>
    public string WithheldOutputMessage { get; set; } = "The response was withheld by a security policy.";
}

/// <summary>Keys for passing the caller on <see cref="ChatOptions.AdditionalProperties"/>.</summary>
public static class SentinelChatOptions
{
    public const string UserId = "sentinel.user_id";
    public const string OwnerId = "sentinel.owner_id";
    public const string AgentId = "sentinel.agent_id";

    /// <summary>Response property holding the strongest action taken: allow, redact, block…</summary>
    public const string Action = "sentinel.action";

    /// <summary>Response property holding the reason, when something was blocked.</summary>
    public const string Reason = "sentinel.reason";

    /// <summary>Attach the authenticated caller to a request. Takes precedence over <see cref="ISentinelCallerProvider"/>.</summary>
    public static ChatOptions WithSentinelCaller(this ChatOptions options, SentinelCaller caller)
    {
        options.AdditionalProperties ??= [];
        options.AdditionalProperties[UserId] = caller.UserId;
        if (caller.OwnerId is not null) options.AdditionalProperties[OwnerId] = caller.OwnerId;
        if (caller.AgentId is not null) options.AdditionalProperties[AgentId] = caller.AgentId;
        return options;
    }
}

/// <summary>
/// Enforces SentinelAI policy around a chat client:
/// <list type="bullet">
/// <item>user input is scanned before the model is called;</item>
/// <item>every <see cref="AIFunction"/> is wrapped so <see cref="ToolGuard"/> authorizes each call as it runs,
/// and its result is scanned before the model reads it;</item>
/// <item>tool calls still present in a response are authorized, so ordering mistakes fail safe;</item>
/// <item>the model's reply is scanned and redacted or withheld.</item>
/// </list>
/// Streaming responses are buffered so the reply can be checked before any of it is shown.
/// </summary>
public sealed class SentinelChatClient(
    IChatClient innerClient,
    SentinelEngine engine,
    ToolGuard guard,
    SentinelChatClientOptions? options = null,
    ISentinelCallerProvider? callers = null,
    IToolApprovalHandler? approvals = null) : DelegatingChatClient(innerClient)
{
    private readonly SentinelEngine _engine = engine;
    private readonly ToolGuard _guard = guard;
    private readonly SentinelChatClientOptions _options = options ?? new();
    private readonly ISentinelCallerProvider? _callers = callers;
    private readonly IToolApprovalHandler? _approvals = approvals;

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        var list = messages as IList<ChatMessage> ?? messages.ToList();
        var caller = ResolveCaller(list, options);
        using var activity = SentinelTelemetry.Source.StartActivity("sentinel.chat");

        var input = await ScanInputAsync(list, caller, cancellationToken);
        if (input?.Action == SecurityAction.Block) return Reply(_options.BlockedInputMessage, input);

        var response = await base.GetResponseAsync(list, WrapTools(options, caller), cancellationToken);
        return (await FilterAsync(response, caller, cancellationToken)).Response;
    }

    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages, ChatOptions? options = null, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var list = messages as IList<ChatMessage> ?? messages.ToList();
        var caller = ResolveCaller(list, options);
        using var activity = SentinelTelemetry.Source.StartActivity("sentinel.chat");

        var input = await ScanInputAsync(list, caller, cancellationToken);
        if (input?.Action == SecurityAction.Block)
        {
            foreach (var u in Reply(_options.BlockedInputMessage, input).ToChatResponseUpdates()) yield return u;
            yield break;
        }

        var updates = new List<ChatResponseUpdate>();
        await foreach (var u in base.GetStreamingResponseAsync(list, WrapTools(options, caller), cancellationToken))
            updates.Add(u);

        var (filtered, changed) = await FilterAsync(updates.ToChatResponse(), caller, cancellationToken);
        foreach (var u in changed ? filtered.ToChatResponseUpdates() : (IEnumerable<ChatResponseUpdate>)updates) yield return u;
    }

    private async Task<SecurityDecision?> ScanInputAsync(IList<ChatMessage> messages, ToolCallerContext caller, CancellationToken ct)
    {
        var turns = messages.Where(m => m.Role == ChatRole.User).Select(m => m.Text).Where(t => !string.IsNullOrWhiteSpace(t))
            .TakeLast(Math.Max(1, _options.UserTurnsToScan)).ToList();
        if (turns.Count == 0) return null;
        return await _engine.ScanAsync(new SecurityScanContext(ContentSource.UserInput, string.Join("\n", turns),
            caller.UserId, caller.AgentId, turns.Count > 1 ? $"conversation ({turns.Count} turns)" : "user message"), ct);
    }

    private async Task<(ChatResponse Response, bool Changed)> FilterAsync(ChatResponse response, ToolCallerContext caller, CancellationToken ct)
    {
        var changed = false;
        var worst = SecurityAction.Allow;

        // A function-invocation loop returns its whole history, including calls it already ran through
        // the guarded functions. Calls without a result were not run here (SentinelAI is inside the loop,
        // or the app runs tools itself), so authorize those before anyone can execute them.
        var completed = response.Messages.SelectMany(m => m.Contents).OfType<FunctionResultContent>()
            .Select(r => r.CallId).ToHashSet();
        foreach (var message in response.Messages)
        {
            for (var i = 0; i < message.Contents.Count; i++)
            {
                if (message.Contents[i] is not FunctionCallContent fc || completed.Contains(fc.CallId)) continue;
                var call = ToToolCall(fc.Name, fc.Arguments);
                var decision = _guard.Evaluate(call, caller);
                worst = Max(worst, decision.PolicyAction);
                var allowed = decision.Action == SecurityAction.Allow
                    || (decision.Action == SecurityAction.RequireApproval && _approvals is not null
                        && await _approvals.ApproveAsync(new ToolApprovalRequest(call, caller, decision), ct));
                if (allowed) continue;
                message.Contents[i] = new TextContent($"[Tool call {fc.Name} was not allowed: {decision.Reason}]");
                changed = true;
            }
        }

        foreach (var message in response.Messages)
        {
            var text = message.Text;
            if (string.IsNullOrWhiteSpace(text)) continue;
            var decision = await _engine.ScanAsync(new SecurityScanContext(ContentSource.ModelOutput, text,
                caller.UserId, caller.AgentId, "model response"), ct);
            worst = Max(worst, decision.PolicyAction);

            if (decision.Action == SecurityAction.Block) return (Reply(_options.WithheldOutputMessage, decision), true);
            if (decision.Action != SecurityAction.Redact) continue;

            var first = IndexOfText(message);
            foreach (var t in message.Contents.OfType<TextContent>().ToList()) message.Contents.Remove(t);
            message.Contents.Insert(Math.Min(first, message.Contents.Count), new TextContent(decision.Content));
            changed = true;
        }

        response.AdditionalProperties ??= [];
        response.AdditionalProperties[SentinelChatOptions.Action] = SentinelTelemetry.Format(worst);
        return (response, changed);
    }

    private ChatOptions? WrapTools(ChatOptions? options, ToolCallerContext caller)
    {
        if (options?.Tools is not { Count: > 0 } tools) return options;
        var clone = options.Clone();
        clone.Tools = tools.Select(t => t is AIFunction f and not GuardedFunction ? new GuardedFunction(f, this, caller) : t).ToList();
        return clone;
    }

    private ToolCallerContext ResolveCaller(IList<ChatMessage> messages, ChatOptions? options)
    {
        var props = options?.AdditionalProperties;
        string? Prop(string key) => props is not null && props.TryGetValue(key, out var v) ? v?.ToString() : null;

        var fromProvider = _callers?.GetCurrentCaller();
        var userId = Prop(SentinelChatOptions.UserId) ?? fromProvider?.UserId ?? "anonymous";
        var ownerId = Prop(SentinelChatOptions.OwnerId) ?? (Prop(SentinelChatOptions.UserId) is null ? fromProvider?.OwnerId : null);
        var agentId = Prop(SentinelChatOptions.AgentId) ?? fromProvider?.AgentId ?? _options.AgentId;
        var latest = messages.LastOrDefault(m => m.Role == ChatRole.User)?.Text ?? "";
        return new ToolCallerContext(userId, ownerId, agentId, latest);
    }

    private async Task<object?> ScanToolResultAsync(string tool, object? result, ToolCallerContext caller, CancellationToken ct)
    {
        var text = result switch
        {
            null => null,
            string s => s,
            JsonElement e => e.ToString(),
            _ => TrySerialize(result),
        };
        if (string.IsNullOrWhiteSpace(text)) return result;

        var decision = await _engine.ScanAsync(new SecurityScanContext(ContentSource.RetrievedDocument, text,
            caller.UserId, caller.AgentId, $"tool:{tool}"), ct);
        return decision.Action is SecurityAction.Quarantine or SecurityAction.Block
            ? $"[Removed by security policy: the result of {tool} contained instructions aimed at the assistant. Treat the action as failed.]"
            : result;
    }

    internal static ToolCall ToToolCall(string name, IEnumerable<KeyValuePair<string, object?>>? arguments) =>
        new(name, (arguments ?? []).ToDictionary(a => a.Key, a => a.Value is JsonElement e ? e : JsonSerializer.SerializeToElement(a.Value)));

    private static ChatResponse Reply(string text, SecurityDecision decision) =>
        new(new ChatMessage(ChatRole.Assistant, text))
        {
            FinishReason = ChatFinishReason.ContentFilter,
            AdditionalProperties = new()
            {
                [SentinelChatOptions.Action] = SentinelTelemetry.Format(decision.PolicyAction),
                [SentinelChatOptions.Reason] = decision.Reason,
            },
        };

    private static int IndexOfText(ChatMessage m)
    {
        for (var i = 0; i < m.Contents.Count; i++) if (m.Contents[i] is TextContent) return i;
        return m.Contents.Count;
    }

    private static string? TrySerialize(object value)
    {
        try { return JsonSerializer.Serialize(value); }
        catch (Exception ex) when (ex is NotSupportedException or InvalidOperationException) { return value.ToString(); }
    }

    private static SecurityAction Max(SecurityAction a, SecurityAction b) => a >= b ? a : b;

    /// <summary>Authorizes each invocation with <see cref="ToolGuard"/> and scans the result.</summary>
    private sealed class GuardedFunction(AIFunction inner, SentinelChatClient owner, ToolCallerContext caller) : DelegatingAIFunction(inner)
    {
        protected override async ValueTask<object?> InvokeCoreAsync(AIFunctionArguments arguments, CancellationToken cancellationToken)
        {
            var call = ToToolCall(Name, arguments);
            var decision = owner._guard.Evaluate(call, caller);

            if (decision.Action == SecurityAction.Block)
                return $"Not executed: blocked by security policy ({decision.Reason}).";

            if (decision.Action == SecurityAction.RequireApproval &&
                (owner._approvals is null || !await owner._approvals.ApproveAsync(new ToolApprovalRequest(call, caller, decision), cancellationToken)))
                return $"Not executed: this action needs human approval ({decision.Reason}).";

            var result = await base.InvokeCoreAsync(arguments, cancellationToken);
            return owner._options.ScanToolResults ? await owner.ScanToolResultAsync(Name, result, caller, cancellationToken) : result;
        }
    }
}
