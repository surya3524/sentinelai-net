using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SentinelAI.Firewall;

/// <summary>
/// Validates documents against a subset of JSON Schema that covers request shapes:
/// type, properties, required, additionalProperties, items, enum, const, minimum, maximum,
/// exclusiveMinimum, exclusiveMaximum, minLength, maxLength, pattern, minItems, maxItems,
/// maxProperties. Unsupported keywords are rejected when the schema loads, so nothing is
/// silently unenforced.
/// </summary>
public sealed class SchemaValidator
{
    private static readonly HashSet<string> Annotations = ["$schema", "$id", "$comment", "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly"];
    private static readonly HashSet<string> Supported =
    [
        "type", "properties", "required", "additionalProperties", "items", "enum", "const",
        "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength",
        "pattern", "minItems", "maxItems", "maxProperties",
    ];

    private readonly JsonObject _schema;
    private readonly Dictionary<string, Regex> _patterns = [];

    public SchemaValidator(string schemaJson, string? name = null)
    {
        _schema = JsonNode.Parse(schemaJson) as JsonObject
            ?? throw new InvalidOperationException($"Schema {name} must be a JSON object.");
        Check(_schema, "#", name);
    }

    public IReadOnlyList<(string Location, string Error)> Validate(JsonNode? instance, string location)
    {
        var errors = new List<(string, string)>();
        Validate(_schema, instance, location, errors);
        return errors;
    }

    private void Check(JsonObject schema, string at, string? name)
    {
        foreach (var (key, value) in schema)
        {
            if (Annotations.Contains(key)) continue;
            if (!Supported.Contains(key))
                throw new InvalidOperationException($"Schema {name}: keyword '{key}' at {at} is not supported by SentinelAI.");
            switch (key)
            {
                case "properties" when value is JsonObject props:
                    foreach (var (p, s) in props)
                        if (s is JsonObject o) Check(o, $"{at}/properties/{p}", name);
                    break;
                case "items" or "additionalProperties" when value is JsonObject sub:
                    Check(sub, $"{at}/{key}", name);
                    break;
                case "pattern":
                    var pattern = value!.GetValue<string>();
                    _patterns[pattern] = new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
                    break;
            }
        }
    }

    private void Validate(JsonObject schema, JsonNode? node, string loc, List<(string, string)> errors)
    {
        if (schema["type"] is { } typeNode)
        {
            var types = typeNode is JsonArray arr ? arr.Select(t => t!.GetValue<string>()).ToList() : [typeNode.GetValue<string>()];
            if (!types.Any(t => Is(node, t)))
            {
                errors.Add((loc, $"expected {string.Join(" or ", types)}, got {Describe(node)}"));
                return; // other keywords would only add noise
            }
        }

        if (schema["enum"] is JsonArray options && !options.Any(o => JsonNode.DeepEquals(o, node)))
            errors.Add((loc, "value is not one of the allowed values"));
        if (schema.TryGetPropertyValue("const", out var c) && !JsonNode.DeepEquals(c, node))
            errors.Add((loc, "value is not the required constant"));

        switch (node)
        {
            case JsonValue v when TryNumber(v, out var n):
                if (Num(schema, "minimum") is { } min && n < min) errors.Add((loc, $"must be ≥ {min}"));
                if (Num(schema, "maximum") is { } max && n > max) errors.Add((loc, $"must be ≤ {max}"));
                if (Num(schema, "exclusiveMinimum") is { } emin && n <= emin) errors.Add((loc, $"must be > {emin}"));
                if (Num(schema, "exclusiveMaximum") is { } emax && n >= emax) errors.Add((loc, $"must be < {emax}"));
                break;
            case JsonValue v when v.TryGetValue<string>(out var s):
                if (Num(schema, "minLength") is { } minL && s.Length < minL) errors.Add((loc, $"must be at least {minL} characters"));
                if (Num(schema, "maxLength") is { } maxL && s.Length > maxL) errors.Add((loc, $"must be at most {maxL} characters"));
                if (schema["pattern"]?.GetValue<string>() is { } p && !Matches(p, s)) errors.Add((loc, "does not match the required pattern"));
                break;
            case JsonArray a:
                if (Num(schema, "minItems") is { } minI && a.Count < minI) errors.Add((loc, $"must have at least {minI} items"));
                if (Num(schema, "maxItems") is { } maxI && a.Count > maxI) errors.Add((loc, $"must have at most {maxI} items"));
                if (schema["items"] is JsonObject itemSchema)
                    for (var i = 0; i < a.Count; i++) Validate(itemSchema, a[i], $"{loc}[{i}]", errors);
                break;
            case JsonObject o:
                if (Num(schema, "maxProperties") is { } maxP && o.Count > maxP) errors.Add((loc, $"must have at most {maxP} properties"));
                if (schema["required"] is JsonArray req)
                    foreach (var r in req.Select(x => x!.GetValue<string>()).Where(r => !o.ContainsKey(r)))
                        errors.Add(($"{loc}.{r}", "is required"));
                var props = schema["properties"] as JsonObject;
                foreach (var (key, value) in o)
                {
                    if (props?[key] is JsonObject ps) Validate(ps, value, $"{loc}.{key}", errors);
                    else if (schema["additionalProperties"] is JsonValue ap && ap.TryGetValue<bool>(out var allowed) && !allowed)
                        errors.Add(($"{loc}.{key}", "is not an allowed property"));
                    else if (schema["additionalProperties"] is JsonObject apSchema) Validate(apSchema, value, $"{loc}.{key}", errors);
                }
                break;
        }
    }

    private bool Matches(string pattern, string value)
    {
        try { return _patterns[pattern].IsMatch(value); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static bool Is(JsonNode? node, string type) => type switch
    {
        "null" => node is null,
        "object" => node is JsonObject,
        "array" => node is JsonArray,
        "boolean" => node is JsonValue v && v.TryGetValue<bool>(out _),
        "string" => node is JsonValue v && v.TryGetValue<string>(out _),
        "number" => node is JsonValue v && TryNumber(v, out _),
        "integer" => node is JsonValue v && TryNumber(v, out var n) && n == Math.Floor(n),
        _ => throw new InvalidOperationException($"Unknown schema type '{type}'."),
    };

    private static bool TryNumber(JsonValue v, out double n)
    {
        if (v.TryGetValue(out double d)) { n = d; return true; }
        if (v.TryGetValue(out long l)) { n = l; return true; }
        if (v.TryGetValue(out decimal m)) { n = (double)m; return true; }
        // Numbers parsed from JSON text are stored as JsonElement.
        if (v.TryGetValue(out System.Text.Json.JsonElement e) && e.ValueKind == System.Text.Json.JsonValueKind.Number)
        {
            n = e.GetDouble();
            return true;
        }
        n = 0;
        return false;
    }

    private static double? Num(JsonObject schema, string key) =>
        schema[key] is JsonValue v && TryNumber(v, out var n) ? n : null;

    private static string Describe(JsonNode? node) => node switch
    {
        null => "null",
        JsonObject => "object",
        JsonArray => "array",
        JsonValue v when v.TryGetValue<string>(out _) => "string",
        JsonValue v when v.TryGetValue<bool>(out _) => "boolean",
        _ => "number",
    };
}
