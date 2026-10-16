using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SentinelAI.Policy;

public static class PolicyLoader
{
    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static SentinelPolicy FromYaml(string yaml)
    {
        var policy = Yaml.Deserialize<SentinelPolicy>(yaml) ?? new SentinelPolicy();
        // YAML deserialization replaces the dictionary, losing the case-insensitive comparer.
        policy.Tools = new Dictionary<string, ToolPolicy>(policy.Tools, StringComparer.OrdinalIgnoreCase);
        Validate(policy);
        return policy;
    }

    public static SentinelPolicy FromFile(string path) => FromYaml(File.ReadAllText(path));

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
