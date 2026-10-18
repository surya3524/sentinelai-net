using SentinelAI.Policy;

namespace SentinelAI.Firewall;

/// <summary>The <c>api_firewall:</c> section of sentinel.yaml.</summary>
public sealed class ApiFirewallPolicy
{
    /// <summary>Detector actions applied when a detector is not configured.</summary>
    public static readonly IReadOnlyDictionary<string, string> DefaultDetectorActions = new Dictionary<string, string>
    {
        [FindingCategory.TemplateInjection] = "block",
        [FindingCategory.UnsafeDeserialization] = "block",
        [FindingCategory.DangerousUrl] = "block",
        [FindingCategory.PathTraversal] = "block",
        // Shell syntax shows up in legitimate text often enough that it is only recorded by default.
        [FindingCategory.CommandInjection] = "allow",
    };

    /// <summary>Include finding details in blocked responses. Off by default so attackers can't tune payloads against them.</summary>
    public bool ExposeDetails { get; set; }

    public long MaxBodyBytes { get; set; } = 1_048_576;

    /// <summary>Maximum nesting of JSON/YAML documents.</summary>
    public int MaxDepth { get; set; } = 32;

    /// <summary>Maximum values inspected per request (guards against expansion attacks).</summary>
    public int MaxFields { get; set; } = 10_000;

    /// <summary>How many layers of encoding (URL, base64, JSON-in-a-string) are unwrapped and re-inspected.</summary>
    public int MaxDecodeDepth { get; set; } = 3;

    /// <summary>Where quarantined requests are stored, relative to the content root.</summary>
    public string QuarantinePath { get; set; } = "sentinel-quarantine";

    /// <summary>Detector → allow | quarantine | block. "allow" still records findings.</summary>
    public Dictionary<string, string> Detectors { get; set; } = [];

    public UrlPolicy Urls { get; set; } = new();
    public ArchivePolicy Archives { get; set; } = new();

    /// <summary>Per-endpoint rules, first match wins. Requests matching none get the detectors only.</summary>
    public List<EndpointRule> Endpoints { get; set; } = [];

    public SecurityAction ActionFor(string detector) =>
        PolicyLoader.ParseAction(Detectors.TryGetValue(detector, out var a) ? a
            : DefaultDetectorActions.TryGetValue(detector, out var d) ? d : "block");

    internal static void Validate(ApiFirewallPolicy p)
    {
        foreach (var (detector, action) in p.Detectors)
        {
            if (!DefaultDetectorActions.ContainsKey(detector))
                throw new InvalidOperationException($"api_firewall.detectors: unknown detector '{detector}'. Known: {string.Join(", ", DefaultDetectorActions.Keys)}.");
            CheckAction($"api_firewall.detectors.{detector}", action);
        }
        foreach (var e in p.Endpoints)
        {
            if (string.IsNullOrWhiteSpace(e.Path)) throw new InvalidOperationException("api_firewall.endpoints: every endpoint needs a path.");
            CheckAction($"api_firewall.endpoints[{e.Path}].on_schema_violation", e.OnSchemaViolation);
            foreach (var d in e.AllowDetectors.Where(d => !DefaultDetectorActions.ContainsKey(d)))
                throw new InvalidOperationException($"api_firewall.endpoints[{e.Path}].allow_detectors: unknown detector '{d}'.");
        }
        if (p.MaxBodyBytes <= 0 || p.MaxDepth <= 0 || p.MaxFields <= 0)
            throw new InvalidOperationException("api_firewall: limits must be positive.");
    }

    private static void CheckAction(string where, string action)
    {
        var a = PolicyLoader.ParseAction(action);
        if (a is not (SecurityAction.Allow or SecurityAction.Block or SecurityAction.Quarantine))
            throw new InvalidOperationException($"{where}: action must be allow, quarantine or block.");
    }
}

public sealed class UrlPolicy
{
    /// <summary>URL schemes allowed inside request data. Anything else (file, gopher, reference…) is flagged.</summary>
    public List<string> AllowedSchemes { get; set; } = ["http", "https"];

    /// <summary>Flag URLs that point at loopback, private, link-local (cloud metadata) or internal hosts.</summary>
    public bool BlockPrivateNetworks { get; set; } = true;

    /// <summary>Hosts that are always allowed, e.g. your own internal APIs.</summary>
    public List<string> AllowedHosts { get; set; } = [];
}

public sealed class ArchivePolicy
{
    /// <summary>Inspect files inside uploaded .zip archives.</summary>
    public bool Inspect { get; set; } = true;
    public int MaxEntries { get; set; } = 200;
    public long MaxUncompressedBytes { get; set; } = 20_000_000;
    /// <summary>Uncompressed/compressed ratio above which an archive is treated as a zip bomb.</summary>
    public int MaxCompressionRatio { get; set; } = 100;
}

public sealed class EndpointRule
{
    /// <summary>Request path glob: <c>*</c> matches one segment, <c>**</c> any number. E.g. <c>/datasets/*/config</c>.</summary>
    public string Path { get; set; } = "";

    /// <summary>HTTP methods this rule applies to. Empty means all.</summary>
    public List<string> Methods { get; set; } = [];

    /// <summary>Turn the firewall off for this endpoint.</summary>
    public bool Skip { get; set; }

    /// <summary>Allowed request content types (e.g. application/json). Empty means any.</summary>
    public List<string> ContentTypes { get; set; } = [];

    public long? MaxBodyBytes { get; set; }

    /// <summary>JSON Schema file for a JSON or YAML request body, relative to the policy file.</summary>
    public string? SchemaFile { get; set; }

    public UploadRule? Uploads { get; set; }

    /// <summary>block | quarantine | allow, for data that doesn't match the schema.</summary>
    public string OnSchemaViolation { get; set; } = "block";

    /// <summary>Detectors switched off for this endpoint, e.g. template_injection on a template-editing API.</summary>
    public List<string> AllowDetectors { get; set; } = [];
}

public sealed class UploadRule
{
    /// <summary>Allowed file extensions, e.g. [.yaml, .json]. Empty means any.</summary>
    public List<string> AllowedExtensions { get; set; } = [];
    public long? MaxBytes { get; set; }

    /// <summary>JSON Schema every uploaded JSON/YAML file must match.</summary>
    public string? SchemaFile { get; set; }

    /// <summary>Keep a copy of blocked uploads for review.</summary>
    public bool Quarantine { get; set; } = true;
}
