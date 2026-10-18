namespace SentinelAI.Policy;

/// <summary>Root of sentinel.yaml. Property names map to snake_case keys.</summary>
public sealed class SentinelPolicy
{
    /// <summary>"enforce" applies decisions; "audit" records them but allows everything.</summary>
    public string Mode { get; set; } = "enforce";

    public PromptInjectionPolicy PromptInjection { get; set; } = new();
    public ActionPolicy Secrets { get; set; } = new() { Action = "redact" };
    public ActionPolicy Pii { get; set; } = new() { Action = "redact" };
    public ExfiltrationPolicy Exfiltration { get; set; } = new();
    public List<RuleDefinition> Rules { get; set; } = [];
    public List<HttpScannerDefinition> HttpScanners { get; set; } = [];

    /// <summary>Tool name → policy. Tools not listed are blocked (default deny).</summary>
    public Dictionary<string, ToolPolicy> Tools { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Inspection of incoming API requests and uploads (SentinelAI.ApiFirewall).</summary>
    public Firewall.ApiFirewallPolicy ApiFirewall { get; set; } = new();

    /// <summary>Folder relative paths in the policy (such as schema files) resolve against. Set by <see cref="PolicyLoader.FromFile"/>.</summary>
    [YamlDotNet.Serialization.YamlIgnore]
    public string? BaseDirectory { get; set; }

    public bool IsAudit => string.Equals(Mode, "audit", StringComparison.OrdinalIgnoreCase);
}

public sealed class PromptInjectionPolicy
{
    public ThresholdPolicy UserInput { get; set; } = new() { Action = "block", Threshold = 0.8 };
    public ThresholdPolicy RetrievedDocument { get; set; } = new() { Action = "quarantine", Threshold = 0.6 };
    public double HiddenUnicodeWeight { get; set; } = 0.7;
}

public sealed class ThresholdPolicy
{
    public string Action { get; set; } = "block";
    public double Threshold { get; set; } = 0.8;
}

public sealed class ActionPolicy
{
    public string Action { get; set; } = "redact";
}

public sealed class ExfiltrationPolicy
{
    public string Action { get; set; } = "block";
    public List<string> AllowedDomains { get; set; } = [];
    public int MaxQueryLength { get; set; } = 32;
}

public sealed class RuleDefinition
{
    public string Id { get; set; } = "";
    public string Pattern { get; set; } = "";
    public double Weight { get; set; } = 0.5;
    public string? Description { get; set; }
    public List<string> Sources { get; set; } = [];
}

public sealed class HttpScannerDefinition
{
    public string Name { get; set; } = "http";
    public string Url { get; set; } = "";
    public List<string> Sources { get; set; } = [];
    public int TimeoutMs { get; set; } = 1500;
    public bool FailClosed { get; set; }
}

public sealed class ToolPolicy
{
    /// <summary>allow | require_approval | block</summary>
    public string Action { get; set; } = "allow";

    public string Risk { get; set; } = "low";

    /// <summary>Argument that must equal the caller's own customer id.</summary>
    public string? OwnershipArg { get; set; }

    /// <summary>Numeric argument checked against the limits below.</summary>
    public string? AmountArg { get; set; }
    public decimal? MaxAmount { get; set; }
    public decimal? ApprovalAbove { get; set; }

    /// <summary>
    /// At least one keyword must appear in the user's latest message. Stops tool calls the
    /// user never asked for — the usual result of instructions hidden in retrieved content.
    /// </summary>
    public List<string> RequireUserIntent { get; set; } = [];

    /// <summary>Argument holding an email address or URL whose domain must be allowlisted.</summary>
    public string? DestinationArg { get; set; }
    public List<string> AllowedDestinations { get; set; } = [];
}
