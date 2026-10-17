namespace SentinelAI.Tools;

/// <summary>The authenticated identity behind a request.</summary>
/// <param name="UserId">Who is signed in.</param>
/// <param name="OwnerId">The id that ownership-checked tool arguments must equal. Null means ownership checks fail.</param>
/// <param name="AgentId">Optional name of the agent acting for the user.</param>
public sealed record SentinelCaller(string UserId, string? OwnerId = null, string? AgentId = null);

/// <summary>
/// Supplies the current caller. SentinelAI.AspNetCore provides one that reads the signed-in
/// user's claims; implement your own for other hosts.
/// </summary>
public interface ISentinelCallerProvider
{
    SentinelCaller? GetCurrentCaller();
}

/// <summary>A tool call that policy says a human must approve before it runs.</summary>
public sealed record ToolApprovalRequest(ToolCall Call, ToolCallerContext Caller, SecurityDecision Decision);

/// <summary>
/// Decides <c>require_approval</c> tool calls, for example by asking a reviewer and waiting.
/// When none is registered, calls that need approval are not executed (fail closed).
/// </summary>
public interface IToolApprovalHandler
{
    Task<bool> ApproveAsync(ToolApprovalRequest request, CancellationToken cancellationToken);
}
