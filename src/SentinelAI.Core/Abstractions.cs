namespace SentinelAI;

/// <summary>Where a piece of content entered the AI pipeline.</summary>
public enum ContentSource
{
    UserInput,
    RetrievedDocument,
    ModelOutput,
    ToolCall,
    /// <summary>An incoming HTTP request inspected by the API firewall.</summary>
    ApiRequest,
}

/// <summary>Ordered by severity: a higher value wins when findings disagree.</summary>
public enum SecurityAction
{
    Allow = 0,
    Redact = 1,
    RequireApproval = 2,
    Quarantine = 3,
    Block = 4,
}

/// <summary>Finding categories that policy maps to actions.</summary>
public static class FindingCategory
{
    public const string PromptInjection = "prompt_injection";
    public const string Secret = "secret";
    public const string Pii = "pii";
    public const string Exfiltration = "exfiltration";
    public const string ToolPolicy = "tool_policy";

    // API firewall
    public const string TemplateInjection = "template_injection";
    public const string UnsafeDeserialization = "unsafe_deserialization";
    public const string DangerousUrl = "dangerous_url";
    public const string PathTraversal = "path_traversal";
    public const string CommandInjection = "command_injection";
    public const string SchemaViolation = "schema_violation";
    public const string RequestLimit = "request_limit";
}

public sealed record SecurityScanContext(
    ContentSource Source,
    string Content,
    string? UserId = null,
    string? AgentId = null,
    string? SourceName = null);

/// <summary>One thing a scanner noticed. Start/Length mark a span to redact (-1 when not applicable).</summary>
public sealed record Finding(
    string Scanner,
    string Category,
    string Rule,
    double Confidence,
    int Start = -1,
    int Length = 0,
    string? Detail = null);

public sealed record SecurityScanResult(string Scanner, IReadOnlyList<Finding> Findings)
{
    public static SecurityScanResult Clean(string scanner) => new(scanner, []);
}

/// <summary>
/// A detector. Implement this to plug in PromptGuard, LlamaFirewall, Azure Content Safety,
/// an ONNX model or an LLM judge. SentinelAI owns the policy; scanners only report.
/// </summary>
public interface IAiSecurityScanner
{
    string Name { get; }
    bool AppliesTo(ContentSource source);
    Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken);
}

/// <summary>The enforced outcome for one piece of content.</summary>
public sealed record SecurityDecision(
    SecurityAction Action,
    ContentSource Source,
    string Content,
    IReadOnlyList<Finding> Findings,
    string Reason,
    string? SourceName = null,
    bool Enforced = true)
{
    /// <summary>What the policy decided, even in audit mode where it is not enforced.</summary>
    public SecurityAction PolicyAction { get; init; } = Action;
}
