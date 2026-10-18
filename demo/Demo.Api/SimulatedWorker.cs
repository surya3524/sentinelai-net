using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using YamlDotNet.RepresentationModel;

namespace Demo.Api;

/// <summary>"ok" for normal processing, "damage" for what an attacker wanted.</summary>
public sealed record WorkerEffect(string Severity, string Text);

/// <summary>
/// Stands in for the background worker that processes uploaded dataset configs. It parses the
/// upload safely and reports what a naive worker (one that renders templates, follows fsspec
/// references, fetches URLs and uses an unsafe YAML loader) would have done.
///
/// It never renders, fetches, opens or constructs anything. The demo is safe to run anywhere.
/// </summary>
public static partial class SimulatedWorker
{
    public static List<WorkerEffect> Process(string fileName, byte[] content)
    {
        var effects = new List<WorkerEffect>();
        if (fileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) Zip(content, effects);
        else Document(fileName, content, effects);
        if (effects.All(e => e.Severity == "ok")) effects.Insert(0, new("ok", $"Loaded {fileName} and queued it for indexing."));
        return effects;
    }

    private static void Zip(byte[] content, List<WorkerEffect> effects)
    {
        try
        {
            using var archive = new ZipArchive(new MemoryStream(content));
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName.Contains("..") || entry.FullName.StartsWith('/'))
                    effects.Add(new("damage", $"Would extract \"{entry.FullName}\" outside the dataset folder (zip slip): it can overwrite files on the worker."));
                if (entry.Length is > 0 and < 1_000_000)
                {
                    using var s = entry.Open();
                    var buffer = new MemoryStream();
                    s.CopyTo(buffer);
                    Document(entry.Name, buffer.ToArray(), effects);
                }
            }
        }
        catch (InvalidDataException) { effects.Add(new("ok", "Archive was not readable; skipped.")); }
    }

    private static void Document(string fileName, byte[] content, List<WorkerEffect> effects)
    {
        var text = Encoding.UTF8.GetString(content);
        if (fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
        {
            try { Walk(JsonNode.Parse(text), "", effects); }
            catch (System.Text.Json.JsonException) { effects.Add(new("ok", $"{fileName} is not valid JSON; skipped.")); }
            return;
        }
        var yaml = new YamlStream();
        try { yaml.Load(new StringReader(text)); }
        catch (YamlDotNet.Core.YamlException) { effects.Add(new("ok", $"{fileName} is not valid YAML; skipped.")); return; }
        foreach (var doc in yaml.Documents) Walk(doc.RootNode, "", effects);
    }

    private static void Walk(YamlNode node, string path, List<WorkerEffect> effects)
    {
        if (!node.Tag.IsEmpty && node.Tag.Value.Contains("python", StringComparison.OrdinalIgnoreCase))
            effects.Add(new("damage", $"An unsafe YAML loader would construct the Python object {node.Tag.Value} at {Show(path)}: that is how YAML deserialization becomes code execution."));
        switch (node)
        {
            case YamlMappingNode m:
                foreach (var (k, v) in m.Children) Walk(v, $"{path}.{(k as YamlScalarNode)?.Value}", effects);
                break;
            case YamlSequenceNode s:
                var i = 0;
                foreach (var item in s.Children) Walk(item, $"{path}[{i++}]", effects);
                break;
            case YamlScalarNode sc:
                Value(sc.Value ?? "", path, effects);
                break;
        }
    }

    private static void Walk(JsonNode? node, string path, List<WorkerEffect> effects)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var (k, v) in o)
                {
                    if (k == "$type") effects.Add(new("damage", $"A polymorphic deserializer would create the type named at {Show(path)}.$type: a known route to code execution."));
                    Walk(v, $"{path}.{k}", effects);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++) Walk(a[i], $"{path}[{i}]", effects);
                break;
            case JsonValue v when v.TryGetValue<string>(out var s):
                Value(s, path, effects);
                break;
        }
    }

    private static void Value(string value, string path, List<WorkerEffect> effects)
    {
        var decoded = TryBase64(value);
        foreach (var text in decoded is null ? [value] : new[] { value, decoded })
        {
            if (Template().Match(text) is { Success: true } t)
                effects.Add(new("damage", $"Would render {t.Value} at {Show(path)} with the template engine. A real attacker puts code there, and it runs inside the worker (remote code execution)."));
            foreach (Match u in Url().Matches(text))
            {
                var scheme = u.Groups[1].Value.ToLowerInvariant();
                if (scheme is not ("http" or "https"))
                    effects.Add(new("damage", $"Would open {u.Value} at {Show(path)} through an fsspec-style resolver: the uploader chooses which files or references the worker loads."));
                else if (Internal().IsMatch(u.Value))
                    effects.Add(new("damage", $"Would fetch {u.Value} from inside the network (SSRF). Cloud metadata endpoints hand out the worker's credentials."));
            }
            if (Traversal().IsMatch(text))
                effects.Add(new("damage", $"Would read \"{text}\" at {Show(path)}, which is outside the dataset folder."));
        }
    }

    private static string? TryBase64(string s)
    {
        if (s.Length < 16 || s.Length % 4 != 0) return null;
        try
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(s));
            return text.All(c => !char.IsControl(c) || c is '\n' or '\r' or '\t') ? text : null;
        }
        catch (FormatException) { return null; }
    }

    private static string Show(string path) => path.TrimStart('.') is { Length: > 0 } p ? p : "the document root";

    [GeneratedRegex(@"\{\{.+?\}\}|\{%.+?%\}")] private static partial Regex Template();
    [GeneratedRegex(@"([a-zA-Z][a-zA-Z0-9+.\-]*)://\S*")] private static partial Regex Url();
    [GeneratedRegex(@"//(127\.|10\.|169\.254\.|192\.168\.|localhost|metadata)")] private static partial Regex Internal();
    [GeneratedRegex(@"(^|/)\.\.(/|$)")] private static partial Regex Traversal();
}
