using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SentinelAI.Policy;

public static class PolicyLoader
{
    // Unknown keys are an error: in a security policy, a typo must not silently disable a control.
    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .Build();

    /// <summary>
    /// Parses a policy. Omitted settings keep their defaults; an omitted <c>rules</c> key keeps the
    /// built-in starter rules (write <c>rules: []</c> to turn them off).
    /// </summary>
    public static SentinelPolicy FromYaml(string yaml) => Parse(yaml, inheritDefaultRules: true);

    public static SentinelPolicy FromFile(string path) => FromYaml(File.ReadAllText(path));

    /// <summary>The built-in policy: starter rules, redaction on, and no tools allowed.</summary>
    public static SentinelPolicy Default() => Parse(DefaultYaml, inheritDefaultRules: false);

    private static SentinelPolicy Parse(string yaml, bool inheritDefaultRules)
    {
        SentinelPolicy policy;
        try
        {
            policy = Yaml.Deserialize<SentinelPolicy>(yaml) ?? new SentinelPolicy();
        }
        catch (YamlException ex)
        {
            throw new InvalidOperationException($"Invalid SentinelAI policy at line {ex.Start.Line}: {(ex.InnerException ?? ex).Message}", ex);
        }

        if (inheritDefaultRules && !HasTopLevelKey(yaml, "rules")) policy.Rules = Default().Rules;

        // YAML deserialization replaces the dictionary, losing the case-insensitive comparer.
        policy.Tools = new Dictionary<string, ToolPolicy>(policy.Tools, StringComparer.OrdinalIgnoreCase);
        Validate(policy);
        return policy;
    }

    private static bool HasTopLevelKey(string yaml, string key)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        return stream.Documents.Count > 0
            && stream.Documents[0].RootNode is YamlMappingNode map
            && map.Children.Keys.OfType<YamlScalarNode>().Any(k => k.Value == key);
    }

    /// <summary>The built-in policy as YAML, a starting point for your own sentinel.yaml.</summary>
    public static string DefaultYaml
    {
        get
        {
            using var stream = typeof(PolicyLoader).Assembly.GetManifestResourceStream("SentinelAI.default-policy.yaml")
                ?? throw new InvalidOperationException("Built-in policy resource is missing.");
            return new StreamReader(stream).ReadToEnd();
        }
    }

    public static SecurityAction ParseAction(string value) => value.Trim().ToLowerInvariant() switch
    {
        "allow" => SecurityAction.Allow,
        "redact" => SecurityAction.Redact,
        "require_approval" or "require_confirmation" => SecurityAction.RequireApproval,
        "quarantine" => SecurityAction.Quarantine,
        "block" => SecurityAction.Block,
        _ => throw new InvalidOperationException($"Unknown policy action '{value}'."),
    };

    public static ContentSource ParseSource(string value) => value.Trim().ToLowerInvariant() switch
    {
        "user_input" => ContentSource.UserInput,
        "retrieved_document" => ContentSource.RetrievedDocument,
        "model_output" => ContentSource.ModelOutput,
        "tool_call" => ContentSource.ToolCall,
        _ => throw new InvalidOperationException($"Unknown content source '{value}'."),
    };

    public static string FormatSource(ContentSource source) => source switch
    {
        ContentSource.UserInput => "user_input",
        ContentSource.RetrievedDocument => "retrieved_document",
        ContentSource.ModelOutput => "model_output",
        ContentSource.ToolCall => "tool_call",
        _ => source.ToString(),
    };

    private static void Validate(SentinelPolicy p)
    {
        ParseAction(p.PromptInjection.UserInput.Action);
        ParseAction(p.PromptInjection.RetrievedDocument.Action);
        ParseAction(p.Secrets.Action);
        ParseAction(p.Pii.Action);
        ParseAction(p.Exfiltration.Action);
        foreach (var (name, tool) in p.Tools)
        {
            var a = ParseAction(tool.Action);
            if (a is SecurityAction.Redact or SecurityAction.Quarantine)
                throw new InvalidOperationException($"Tool '{name}': action must be allow, require_approval or block.");
        }
        foreach (var r in p.Rules)
        {
            if (string.IsNullOrWhiteSpace(r.Id) || string.IsNullOrWhiteSpace(r.Pattern))
                throw new InvalidOperationException("Every rule needs an id and a pattern.");
            if (r.Weight is <= 0 or > 1) throw new InvalidOperationException($"Rule '{r.Id}': weight must be in (0, 1].");
            r.Sources.ForEach(s => ParseSource(s));
        }
    }
}
