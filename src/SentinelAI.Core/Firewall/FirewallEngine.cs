using System.Collections.Concurrent;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SentinelAI.Policy;
using SentinelAI.Telemetry;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace SentinelAI.Firewall;

/// <summary>
/// One piece of a request: the body, a form field, or an uploaded file. <c>Location</c> says where it came
/// from and is used in findings: <c>body</c>, <c>form.name</c>, <c>file:config.yaml</c>.
/// </summary>
public sealed record RequestPart(string Location, string? ContentType, string? FileName, ReadOnlyMemory<byte> Content, bool IsUpload = false);

public sealed record FirewallRequest(
    string Method,
    string Path,
    IReadOnlyList<KeyValuePair<string, string>> Query,
    IReadOnlyList<RequestPart> Parts,
    string? ContentType = null,
    long BodyLength = 0);

public sealed record FirewallVerdict(
    SecurityAction Action,
    SecurityAction PolicyAction,
    int StatusCode,
    string Reason,
    IReadOnlyList<Finding> Findings,
    EndpointRule? Rule,
    bool Enforced)
{
    public bool Allowed => Action == SecurityAction.Allow;
}

/// <summary>
/// Inspects incoming API requests for content that could make a server run code or reach places it
/// shouldn't: template expressions, unsafe deserialization markers, dangerous URLs, path traversal,
/// and data that breaks the endpoint's schema. Independent of ASP.NET Core; SentinelAI.ApiFirewall
/// runs it as middleware.
/// </summary>
public sealed partial class FirewallEngine
{
    private readonly SentinelPolicy _policy;
    private readonly ApiFirewallPolicy _fw;
    private readonly IRequestDetector[] _detectors;
    private readonly UnsafeDeserializationDetector _deserialization = new();
    private readonly ConcurrentDictionary<string, SchemaValidator> _schemas = new();
    private readonly List<(EndpointRule Rule, Regex Path)> _rules;

    public FirewallEngine(SentinelPolicy policy)
    {
        _policy = policy;
        _fw = policy.ApiFirewall;
        _detectors =
        [
            new TemplateInjectionDetector(),
            _deserialization,
            new DangerousUrlDetector(_fw.Urls),
            new PathTraversalDetector(),
            new CommandInjectionDetector(),
        ];
        _rules = _fw.Endpoints.Select(r => (r, Glob(r.Path))).ToList();
        // Load schemas now so a bad schema fails at startup, not on the first request.
        foreach (var r in _fw.Endpoints)
        {
            if (r.SchemaFile is { } s) Schema(s);
            if (r.Uploads?.SchemaFile is { } u) Schema(u);
        }
    }

    public ApiFirewallPolicy Policy => _fw;

    public EndpointRule? Match(string method, string path) =>
        _rules.FirstOrDefault(r => r.Path.IsMatch(path) &&
            (r.Rule.Methods.Count == 0 || r.Rule.Methods.Any(m => string.Equals(m, method, StringComparison.OrdinalIgnoreCase)))).Rule;

    /// <summary>The body size limit for a request, so hosts can stop reading early.</summary>
    public long MaxBodyBytes(string method, string path) => Match(method, path)?.MaxBodyBytes ?? _fw.MaxBodyBytes;

    public FirewallVerdict Inspect(FirewallRequest request)
    {
        using var activity = SentinelTelemetry.Source.StartActivity("sentinel.firewall");
        var rule = Match(request.Method, request.Path);
        if (rule?.Skip == true) return Finish(request, rule, [], 200);

        var findings = new List<Finding>();
        var walker = new Walker(this, findings);

        if (rule is { ContentTypes.Count: > 0 } && request.Parts.Count > 0 &&
            !rule.ContentTypes.Any(ct => (request.ContentType ?? "").StartsWith(ct, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(Limit("content-type", $"content type {request.ContentType ?? "(none)"} is not accepted here"));
            return Finish(request, rule, findings, 415);
        }

        var maxBody = rule?.MaxBodyBytes ?? _fw.MaxBodyBytes;
        if (request.BodyLength > maxBody)
        {
            findings.Add(Limit("body-size", $"body is {request.BodyLength} bytes, limit {maxBody}"));
            return Finish(request, rule, findings, 413);
        }

        foreach (var (key, value) in request.Query)
            walker.Text(new RequestValue($"query.{key}", value), 0);

        foreach (var part in request.Parts)
        {
            if (part.IsUpload && !CheckUpload(part, rule, findings)) continue;
            var schemaFile = part.IsUpload ? rule?.Uploads?.SchemaFile : part.Location == "body" ? rule?.SchemaFile : null;
            walker.Part(part, schemaFile, depth: 0);
        }

        return Finish(request, rule, findings, 400);
    }

    private bool CheckUpload(RequestPart part, EndpointRule? rule, List<Finding> findings)
    {
        if (rule?.Uploads is not { } up) return true;
        var ext = Path.GetExtension(part.FileName ?? "").ToLowerInvariant();
        if (up.AllowedExtensions.Count > 0 && !up.AllowedExtensions.Any(e => string.Equals(e, ext, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "file-type", 1.0,
                Detail: $"{part.Location}: {(ext == "" ? "no extension" : ext)} files are not accepted"));
            return false;
        }
        if (up.MaxBytes is { } max && part.Content.Length > max)
        {
            findings.Add(Limit("file-size", $"{part.Location}: {part.Content.Length} bytes, limit {max}"));
            return false;
        }
        return true;
    }

    private FirewallVerdict Finish(FirewallRequest request, EndpointRule? rule, List<Finding> findings, int blockStatus)
    {
        var allowed = rule?.AllowDetectors.ToHashSet() ?? [];
        var worst = SecurityAction.Allow;
        var keepCopy = false;
        foreach (var f in findings)
        {
            var action = f.Category switch
            {
                FindingCategory.RequestLimit => SecurityAction.Block,
                FindingCategory.SchemaViolation => PolicyLoader.ParseAction(rule?.OnSchemaViolation ?? "block"),
                var c when allowed.Contains(c) => SecurityAction.Allow,
                var c => _fw.ActionFor(c),
            };
            if (action > worst) worst = action;
            keepCopy |= action == SecurityAction.Quarantine;
        }
        // Quarantine means "reject and keep a copy". If any finding asks for that, keep the copy even when
        // another finding blocks outright; unless the endpoint opts out of keeping uploads.
        if (worst >= SecurityAction.Quarantine)
            worst = keepCopy && blockStatus == 400 && rule?.Uploads is not { Quarantine: false } ? SecurityAction.Quarantine : SecurityAction.Block;

        var enforced = !_policy.IsAudit;
        var action2 = enforced ? worst : SecurityAction.Allow;
        var reason = findings.Count == 0 ? "no findings"
            : string.Join("; ", findings.GroupBy(f => f.Category).Select(g => $"{g.Key}: {string.Join(", ", g.Select(f => f.Detail).Distinct().Take(3))}"));
        var status = action2 == SecurityAction.Allow ? 200 : blockStatus;

        SentinelTelemetry.Record(new SecurityDecision(action2, ContentSource.ApiRequest, "", findings, reason,
            $"{request.Method} {request.Path}", enforced) { PolicyAction = worst }, userId: null, agentId: null);
        return new FirewallVerdict(action2, worst, status, reason, findings, rule, enforced);
    }

    private static Finding Limit(string rule, string detail) =>
        new("api_firewall", FindingCategory.RequestLimit, rule, 1.0, Detail: detail);

    private SchemaValidator Schema(string file) => _schemas.GetOrAdd(file, f =>
    {
        var path = Path.IsPathRooted(f) ? f : Path.Combine(_policy.BaseDirectory ?? AppContext.BaseDirectory, f);
        return new SchemaValidator(File.ReadAllText(path), f);
    });

    private static Regex Glob(string pattern)
    {
        var sb = new StringBuilder("^");
        for (var i = 0; i < pattern.Length; i++)
        {
            if (pattern[i] == '*' && i + 1 < pattern.Length && pattern[i + 1] == '*') { sb.Append(".*"); i++; }
            else if (pattern[i] == '*') sb.Append("[^/]+");
            else sb.Append(Regex.Escape(pattern[i].ToString()));
        }
        return new Regex(sb.Append("/?$").ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    /// <summary>Walks one request, with a shared budget so nested or expanding content can't exhaust the server.</summary>
    private sealed partial class Walker(FirewallEngine engine, List<Finding> findings)
    {
        private int _values;
        private bool _overBudget;

        public void Part(RequestPart part, string? schemaFile, int depth)
        {
            var kind = Kind(part);
            switch (kind)
            {
                case "zip":
                    Zip(part, depth);
                    return;
                case "json":
                case "yaml":
                    var node = kind == "json" ? ParseJson(part) : ParseYaml(part);
                    if (node is { } doc)
                    {
                        if (schemaFile is not null)
                            foreach (var (loc, err) in engine.Schema(schemaFile).Validate(doc.Root, part.Location))
                                findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "schema", 1.0, Detail: $"{loc}: {err}"));
                        Node(doc.Root, part.Location, depth);
                    }
                    else if (schemaFile is not null)
                        findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "unparseable", 1.0, Detail: $"{part.Location}: not valid {kind}"));
                    return;
                default:
                    if (TryText(part.Content.Span, out var text)) Text(new RequestValue(part.Location, text), depth);
                    else engine._deserialization.InspectBytes(part.Content.Span, new RequestValue(part.Location, ""), findings);
                    return;
            }
        }

        public void Text(RequestValue v, int depth)
        {
            if (!Budget()) return;
            foreach (var d in engine._detectors) d.Inspect(v, findings);
            if (v.IsKey || depth >= engine._fw.MaxDecodeDepth) return;

            var t = v.Text.Trim();
            // URL-encoded payloads.
            if (t.Contains('%') && PercentEscape().IsMatch(t))
            {
                var decoded = WebUtility.UrlDecode(t);
                if (decoded != t) Text(v with { Location = $"{v.Location} (url-decoded)", Text = decoded }, depth + 1);
            }
            // JSON hidden inside a string.
            if (t.Length > 1 && (t[0] == '{' && t[^1] == '}' || t[0] == '[' && t[^1] == ']'))
            {
                try
                {
                    var node = JsonNode.Parse(t, documentOptions: new JsonDocumentOptions { MaxDepth = engine._fw.MaxDepth });
                    Node(node, $"{v.Location} (json)", depth + 1);
                }
                catch (JsonException) { }
            }
            // Base64-wrapped payloads.
            if (t.Length >= 16 && t.Length % 4 == 0 && Base64().IsMatch(t))
            {
                try
                {
                    var bytes = Convert.FromBase64String(t.Replace('-', '+').Replace('_', '/'));
                    var loc = $"{v.Location} (base64)";
                    engine._deserialization.InspectBytes(bytes, new RequestValue(loc, ""), findings);
                    if (TryText(bytes, out var inner)) Text(new RequestValue(loc, inner), depth + 1);
                }
                catch (FormatException) { }
            }
        }

        private void Node(JsonNode? node, string loc, int depth)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (var (key, value) in o)
                    {
                        Text(new RequestValue($"{loc}.{key}", key, IsKey: true), depth);
                        Node(value, $"{loc}.{key}", depth);
                    }
                    break;
                case JsonArray a:
                    for (var i = 0; i < a.Count; i++) Node(a[i], $"{loc}[{i}]", depth);
                    break;
                case JsonValue v when v.TryGetValue<string>(out var s):
                    Text(new RequestValue(loc, s), depth);
                    break;
                case JsonValue v when v.TryGetValue<JsonElement>(out var e) && e.ValueKind == JsonValueKind.String:
                    Text(new RequestValue(loc, e.GetString()!), depth);
                    break;
            }
        }

        private sealed record Doc(JsonNode? Root);

        private Doc? ParseJson(RequestPart part)
        {
            try
            {
                var node = JsonNode.Parse(part.Content.Span, documentOptions: new JsonDocumentOptions { MaxDepth = engine._fw.MaxDepth });
                CheckDuplicateKeys(node, part.Location);
                return new Doc(node);
            }
            catch (JsonException ex) when (ex.Message.Contains("depth", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Limit("nesting-depth", $"{part.Location}: nested deeper than {engine._fw.MaxDepth}"));
                return null;
            }
            catch (JsonException) { return null; }
        }

        // Duplicate keys are resolved differently by different parsers, a classic way to slip a value
        // past validation. System.Text.Json reports them when the object is first read.
        private void CheckDuplicateKeys(JsonNode? node, string loc)
        {
            try
            {
                switch (node)
                {
                    case JsonObject o: foreach (var (k, v) in o) CheckDuplicateKeys(v, $"{loc}.{k}"); break;
                    case JsonArray a: for (var i = 0; i < a.Count; i++) CheckDuplicateKeys(a[i], $"{loc}[{i}]"); break;
                }
            }
            catch (ArgumentException)
            {
                findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "duplicate-key", 1.0, Detail: $"{loc}: duplicate keys"));
                throw new JsonException("duplicate keys");
            }
        }

        private Doc? ParseYaml(RequestPart part)
        {
            if (!TryText(part.Content.Span, out var text)) return null;
            var stream = new YamlStream();
            try { stream.Load(new StringReader(text)); }
            catch (YamlException) { return null; }
            if (stream.Documents.Count == 0) return new Doc(null);
            if (stream.Documents.Count > 1)
                findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "multiple-documents", 1.0, Detail: $"{part.Location}: {stream.Documents.Count} YAML documents"));
            return new Doc(Yaml(stream.Documents[0].RootNode, part.Location, 0));
        }

        // Converts YAML to JSON with YAML 1.2 core-schema typing (so a schema can tell 42 from "42"),
        // reporting non-standard tags. Shared alias nodes count against the budget every time they're visited.
        private JsonNode? Yaml(YamlNode node, string loc, int depth)
        {
            if (depth > engine._fw.MaxDepth)
            {
                findings.Add(Limit("nesting-depth", $"{loc}: nested deeper than {engine._fw.MaxDepth}"));
                return null;
            }
            if (!Budget()) return null;

            var tag = node.Tag.IsEmpty ? null : node.Tag.Value;
            if (tag is not null && tag != "!" && !StandardTag().IsMatch(tag))
                findings.Add(UnsafeDeserializationDetector.YamlTag(tag, new RequestValue(loc, "")));

            switch (node)
            {
                case YamlMappingNode m:
                    var obj = new JsonObject();
                    foreach (var (k, v) in m.Children)
                    {
                        var key = (k as YamlScalarNode)?.Value ?? k.ToString();
                        if (obj.ContainsKey(key))
                        {
                            findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "duplicate-key", 1.0, Detail: $"{loc}.{key}: duplicate keys"));
                            continue;
                        }
                        obj[key] = Yaml(v, $"{loc}.{key}", depth + 1);
                    }
                    return obj;
                case YamlSequenceNode s:
                    var arr = new JsonArray();
                    var i = 0;
                    foreach (var item in s.Children) arr.Add(Yaml(item, $"{loc}[{i++}]", depth + 1));
                    return arr;
                case YamlScalarNode sc:
                    var value = sc.Value ?? "";
                    if (sc.Style != ScalarStyle.Plain || tag is not null) return JsonValue.Create(value);
                    if (value is "" or "~" or "null" or "Null" or "NULL") return null;
                    if (value is "true" or "True" or "TRUE") return JsonValue.Create(true);
                    if (value is "false" or "False" or "FALSE") return JsonValue.Create(false);
                    if (YamlInt().IsMatch(value) && long.TryParse(value, out var l)) return JsonValue.Create(l);
                    if (YamlFloat().IsMatch(value) && double.TryParse(value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d))
                        return JsonValue.Create(d);
                    return JsonValue.Create(value);
                default:
                    return null;
            }
        }

        private void Zip(RequestPart part, int depth)
        {
            var policy = engine._fw.Archives;
            if (!policy.Inspect) return;
            try
            {
                using var archive = new ZipArchive(new MemoryStream(part.Content.ToArray()), ZipArchiveMode.Read);
                if (archive.Entries.Count > policy.MaxEntries)
                {
                    findings.Add(Limit("archive-entries", $"{part.Location}: {archive.Entries.Count} entries, limit {policy.MaxEntries}"));
                    return;
                }
                long total = 0;
                foreach (var entry in archive.Entries)
                {
                    var name = $"{part.Location}!/{entry.FullName}";
                    Text(new RequestValue($"{name} (entry name)", entry.FullName), depth);
                    if (entry.Length == 0) continue;
                    total += entry.Length;
                    var ratio = entry.CompressedLength == 0 ? int.MaxValue : entry.Length / Math.Max(1, entry.CompressedLength);
                    if (total > policy.MaxUncompressedBytes || ratio > policy.MaxCompressionRatio)
                    {
                        findings.Add(Limit("archive-size", $"{name}: expands too much (possible zip bomb)"));
                        return;
                    }
                    using var s = entry.Open();
                    var buffer = new MemoryStream();
                    s.CopyTo(buffer);
                    Part(new RequestPart(name, null, entry.Name, buffer.ToArray(), IsUpload: true), schemaFile: null, depth + 1);
                }
            }
            catch (InvalidDataException)
            {
                findings.Add(new Finding("api_firewall", FindingCategory.SchemaViolation, "unparseable", 1.0, Detail: $"{part.Location}: not a valid zip archive"));
            }
        }

        private bool Budget()
        {
            if (++_values <= engine._fw.MaxFields) return true;
            if (!_overBudget)
            {
                _overBudget = true;
                findings.Add(Limit("value-count", $"more than {engine._fw.MaxFields} values"));
            }
            return false;
        }

        private static string Kind(RequestPart p)
        {
            var ct = (p.ContentType ?? "").ToLowerInvariant();
            var ext = Path.GetExtension(p.FileName ?? "").ToLowerInvariant();
            if (ct.Contains("zip") || ext == ".zip") return "zip";
            if (ct.Contains("json") || ext == ".json") return "json";
            if (ct.Contains("yaml") || ext is ".yaml" or ".yml") return "yaml";
            return "text";
        }

        private static bool TryText(ReadOnlySpan<byte> bytes, out string text)
        {
            text = "";
            if (bytes.IsEmpty) return false;
            try { text = new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes); }
            catch (DecoderFallbackException) { return false; }
            var control = text.Count(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t' or '\0'));
            return control <= text.Length / 20;
        }

        [GeneratedRegex(@"%[0-9a-fA-F]{2}")] private static partial Regex PercentEscape();
        [GeneratedRegex(@"^[A-Za-z0-9+/_-]+={0,2}$")] private static partial Regex Base64();
        [GeneratedRegex(@"^tag:yaml\.org,2002:(str|int|float|bool|null|map|seq|binary|timestamp|omap|set|merge)$")] private static partial Regex StandardTag();
        [GeneratedRegex(@"^[-+]?[0-9]+$")] private static partial Regex YamlInt();
        [GeneratedRegex(@"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")] private static partial Regex YamlFloat();
    }
}
