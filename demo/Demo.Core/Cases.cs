using System.Text.Json;
using System.Text.Json.Serialization;

namespace Demo.Agent;

/// <summary>
/// One demo scenario. Turns are what the user sends; Document is content injected into the
/// knowledge base for this run; CompromisedEffect is what a manipulated model would do.
/// </summary>
public sealed record AttackCase(
    string Id,
    string Title,
    string Kind,
    string Category,
    List<string> Turns,
    string? Technique = null,
    string? Reference = null,
    CaseDocument? Document = null,
    CaseEffect? CompromisedEffect = null,
    string? Expected = null,
    string? Notes = null)
{
    [JsonIgnore] public bool IsAttack => string.Equals(Kind, "attack", StringComparison.OrdinalIgnoreCase);
}

public sealed record CaseDocument(string Name, string Content);

public sealed record CaseEffect(string? Output = null, CaseToolCall? ToolCall = null);

public sealed record CaseToolCall(string Name, Dictionary<string, JsonElement> Arguments);

/// <summary>
/// Case files, each holding { "cases": [ ... ] }. The source is re-read on every Load, so
/// with a folder source, edits show up live while presenting.
/// </summary>
public sealed class CaseCatalog(Func<IEnumerable<string>> readFiles)
{
    /// <summary>Every *.json file in a folder, in name order.</summary>
    public CaseCatalog(string directory)
        : this(() => Directory.Exists(directory)
            ? Directory.EnumerateFiles(directory, "*.json").Order().Select(File.ReadAllText)
            : []) { }

    public IReadOnlyList<AttackCase> Load()
    {
        var all = new List<AttackCase>();
        foreach (var json in readFiles())
        {
            var doc = JsonSerializer.Deserialize<CaseFile>(json, Json.Options);
            if (doc?.Cases is null) continue;
            all.AddRange(doc.Cases.Where(c => c.Turns is { Count: > 0 }));
        }
        return all;
    }

    public AttackCase? Find(string id) => Load().FirstOrDefault(c => c.Id == id);

    private sealed record CaseFile(List<AttackCase>? Cases);
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = Configure(new JsonSerializerOptions(JsonSerializerDefaults.Web));

    public static JsonSerializerOptions Configure(JsonSerializerOptions o)
    {
        o.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
        o.ReadCommentHandling = JsonCommentHandling.Skip;
        o.AllowTrailingCommas = true;
        o.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        return o;
    }
}
