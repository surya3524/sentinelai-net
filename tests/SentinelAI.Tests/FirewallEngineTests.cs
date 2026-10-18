using System.IO.Compression;
using System.Text;
using SentinelAI.Firewall;
using SentinelAI.Policy;

namespace SentinelAI.Tests;

/// <summary>
/// Inputs here are inert probes ({{ 7 * 7 }}, harmless tags, metadata URLs) that exercise the
/// detectors without being working exploits.
/// </summary>
public class FirewallEngineTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("sentinel-fw-").FullName;

    private const string ConfigSchema = """
        {
          "type": "object",
          "required": ["name", "data_files"],
          "additionalProperties": false,
          "properties": {
            "name": { "type": "string", "maxLength": 64, "pattern": "^[a-z0-9-]+$" },
            "data_files": {
              "type": "array", "maxItems": 50,
              "items": {
                "type": "object", "additionalProperties": false, "required": ["path"],
                "properties": {
                  "path":   { "type": "string", "pattern": "^[A-Za-z0-9_./-]+$" },
                  "offset": { "type": "integer", "minimum": 0 },
                  "length": { "type": "integer", "minimum": 0 }
                }
              }
            }
          }
        }
        """;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private FirewallEngine Engine(string firewallYaml = "", string mode = "enforce")
    {
        File.WriteAllText(Path.Combine(_dir, "config.schema.json"), ConfigSchema);
        var yaml = $"mode: {mode}\napi_firewall:\n  endpoints:\n    - path: /datasets/*/config\n      uploads: {{ allowed_extensions: [.yaml, .yml, .json, .zip], schema_file: config.schema.json }}\n    - path: /templates/**\n      allow_detectors: [template_injection]\n{firewallYaml}";
        var policyPath = Path.Combine(_dir, "sentinel.yaml");
        File.WriteAllText(policyPath, yaml);
        return new FirewallEngine(PolicyLoader.FromFile(policyPath));
    }

    private static FirewallRequest Json(string json, string path = "/api/items", string method = "POST") =>
        new(method, path, [], [new RequestPart("body", "application/json", null, Encoding.UTF8.GetBytes(json))], "application/json", json.Length);

    private static FirewallRequest Upload(string fileName, byte[] content, string path = "/datasets/imdb/config") =>
        new("POST", path, [], [new RequestPart($"file:{fileName}", null, fileName, content, IsUpload: true)], "multipart/form-data", content.Length);

    private static FirewallRequest Upload(string fileName, string content, string path = "/datasets/imdb/config") =>
        Upload(fileName, Encoding.UTF8.GetBytes(content), path);

    private static void AssertBlocked(FirewallVerdict v, string category)
    {
        Assert.Equal(SecurityAction.Block, v.Action);
        Assert.Contains(v.Findings, f => f.Category == category);
    }

    [Fact]
    public void Benign_json_passes()
    {
        var v = Engine().Inspect(Json("""{ "name": "Wireless headphones", "price": 129.99, "url": "https://example.com/p/1", "tags": ["audio", "sale"] }"""));
        Assert.True(v.Allowed);
        Assert.Empty(v.Findings);
    }

    [Fact]
    public void Benign_dataset_config_passes()
    {
        var yaml = "name: imdb\ndata_files:\n  - path: data/train.parquet\n    offset: 0\n    length: 1024\n";
        Assert.True(Engine().Inspect(Upload("config.yaml", yaml)).Allowed);
    }

    [Fact]
    public void Template_in_a_numeric_field_of_an_uploaded_config_is_blocked_twice_over()
    {
        // The Hugging Face pattern: a template expression where a number belongs.
        var yaml = "name: imdb\ndata_files:\n  - path: data/train.parquet\n    offset: \"{{ 7 * 7 }}\"\n";
        var v = Engine().Inspect(Upload("config.yaml", yaml));

        AssertBlocked(v, FindingCategory.TemplateInjection);
        Assert.Contains(v.Findings, f => f.Category == FindingCategory.SchemaViolation && f.Detail!.Contains("data_files[0].offset: expected integer"));
    }

    [Fact]
    public void Template_is_caught_even_without_a_schema()
    {
        AssertBlocked(Engine().Inspect(Json("""{ "title": "{% if 1 %}x{% endif %}" }""")), FindingCategory.TemplateInjection);
    }

    [Theory]
    [InlineData("reference://dataset.json")]
    [InlineData("file:///etc/hostname")]
    [InlineData("gopher://internal:70/x")]
    [InlineData("simplecache::reference://x")]
    public void Non_web_url_schemes_are_blocked(string url)
    {
        AssertBlocked(Engine().Inspect(Json($$"""{ "source": "{{url}}" }""")), FindingCategory.DangerousUrl);
    }

    [Theory]
    [InlineData("http://169.254.169.254/latest/meta-data/")]
    [InlineData("http://127.0.0.1:8080/admin")]
    [InlineData("http://10.0.0.5/")]
    [InlineData("http://localhost/")]
    [InlineData("http://metadata.google.internal/")]
    [InlineData("http://[::1]/")]
    [InlineData("http://2852039166/")] // 169.254.169.254 as a decimal
    public void Urls_to_internal_hosts_are_blocked(string url)
    {
        AssertBlocked(Engine().Inspect(Json($$"""{ "webhook": "{{url}}" }""")), FindingCategory.DangerousUrl);
    }

    [Fact]
    public void Allowed_internal_host_passes()
    {
        var engine = Engine("  urls: { allowed_hosts: [10.0.0.5] }\n");
        Assert.True(engine.Inspect(Json("""{ "webhook": "http://10.0.0.5/hook" }""")).Allowed);
    }

    [Theory]
    [InlineData("../../etc/passwd")]
    [InlineData("data/../../secret")]
    [InlineData("..\\..\\windows\\win.ini")]
    public void Path_traversal_is_blocked(string path)
    {
        AssertBlocked(Engine().Inspect(Json($$"""{ "path": {{System.Text.Json.JsonSerializer.Serialize(path)}} }""")), FindingCategory.PathTraversal);
    }

    [Fact]
    public void Prose_with_two_dots_passes()
    {
        Assert.True(Engine().Inspect(Json("""{ "comment": "Wait.. what? See the docs folder for details." }""")).Allowed);
    }

    [Fact]
    public void Url_encoded_traversal_is_decoded_and_blocked()
    {
        var v = Engine().Inspect(Json("""{ "path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd" }"""));
        AssertBlocked(v, FindingCategory.PathTraversal);
        Assert.Contains(v.Findings, f => f.Detail!.Contains("(url-decoded)"));
    }

    [Fact]
    public void Base64_wrapped_template_is_decoded_and_blocked()
    {
        var wrapped = Convert.ToBase64String(Encoding.UTF8.GetBytes("offset = {{ 7 * 7 }}"));
        var v = Engine().Inspect(Json($$"""{ "blob": "{{wrapped}}" }"""));
        AssertBlocked(v, FindingCategory.TemplateInjection);
        Assert.Contains(v.Findings, f => f.Detail!.Contains("(base64)"));
    }

    [Fact]
    public void Json_inside_a_string_is_parsed_and_inspected()
    {
        var v = Engine().Inspect(Json("""{ "settings": "{\"source\": \"reference://x\"}" }"""));
        AssertBlocked(v, FindingCategory.DangerousUrl);
    }

    [Fact]
    public void Yaml_language_tags_are_blocked()
    {
        var v = Engine().Inspect(Upload("config.yaml", "name: imdb\ndata_files: []\nextra: !!python/object:datetime.date {}\n"));
        AssertBlocked(v, FindingCategory.UnsafeDeserialization);
        Assert.Contains(v.Findings, f => f.Rule == "yaml-language-tag");
    }

    [Fact]
    public void Polymorphic_type_hints_in_json_are_blocked()
    {
        var v = Engine().Inspect(Json("""{ "item": { "$type": "Some.Type, SomeAssembly", "name": "x" } }"""));
        AssertBlocked(v, FindingCategory.UnsafeDeserialization);
    }

    [Fact]
    public void Serialized_object_headers_in_base64_are_blocked()
    {
        var javaHeader = Convert.ToBase64String([0xAC, 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x10, 0x41, 0x42, 0x43, 0x44]);
        AssertBlocked(Engine().Inspect(Json($$"""{ "state": "{{javaHeader}}" }""")), FindingCategory.UnsafeDeserialization);
    }

    [Fact]
    public void Duplicate_json_keys_are_rejected()
    {
        var v = Engine().Inspect(Json("""{ "role": "user", "role": "admin" }"""));
        Assert.Equal(SecurityAction.Block, v.Action);
        Assert.Contains(v.Findings, f => f.Rule == "duplicate-key");
    }

    [Fact]
    public void Unknown_fields_fail_the_schema()
    {
        var v = Engine().Inspect(Upload("config.json", """{ "name": "imdb", "data_files": [], "loader_script": "x" }"""));
        Assert.Contains(v.Findings, f => f.Detail!.Contains("loader_script: is not an allowed property"));
        Assert.Equal(SecurityAction.Block, v.Action);
    }

    [Fact]
    public void Disallowed_upload_types_are_rejected()
    {
        var v = Engine().Inspect(Upload("loader.py", "print('hi')"));
        Assert.Contains(v.Findings, f => f.Rule == "file-type");
        Assert.Equal(SecurityAction.Block, v.Action);
    }

    [Fact]
    public void Files_inside_zip_uploads_are_inspected_including_entry_names()
    {
        var zip = new MemoryStream();
        using (var archive = new ZipArchive(zip, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var w = new StreamWriter(archive.CreateEntry("configs/a.yaml").Open()))
                w.Write("name: imdb\nnote: \"{{ 7 * 7 }}\"\n");
            using (var w = new StreamWriter(archive.CreateEntry("../outside.txt").Open()))
                w.Write("hello");
        }

        var v = Engine().Inspect(Upload("bundle.zip", zip.ToArray()));
        Assert.Contains(v.Findings, f => f.Category == FindingCategory.TemplateInjection && f.Detail!.Contains("bundle.zip!/configs/a.yaml"));
        Assert.Contains(v.Findings, f => f.Category == FindingCategory.PathTraversal && f.Detail!.Contains("entry name"));
        Assert.Equal(SecurityAction.Block, v.Action);
    }

    [Fact]
    public void Yaml_alias_expansion_hits_the_value_budget()
    {
        var engine = Engine("  max_fields: 200\n");
        var yaml = new StringBuilder("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for (var i = 1; i < 6; i++)
            yaml.Append($"{(char)('a' + i)}: &{(char)('a' + i)} [{string.Join(", ", Enumerable.Repeat($"*{(char)('a' + i - 1)}", 10))}]\n");
        var v = engine.Inspect(new FirewallRequest("POST", "/api/import", [],
            [new RequestPart("body", "application/yaml", null, Encoding.UTF8.GetBytes(yaml.ToString()))], "application/yaml"));
        Assert.Contains(v.Findings, f => f.Rule == "value-count");
        Assert.Equal(SecurityAction.Block, v.Action);
    }

    [Fact]
    public void Deep_nesting_is_rejected()
    {
        var engine = Engine("  max_depth: 8\n");
        var json = new string('[', 20) + new string(']', 20);
        var v = engine.Inspect(Json(json));
        Assert.Contains(v.Findings, f => f.Rule == "nesting-depth");
    }

    [Fact]
    public void Query_string_values_are_inspected()
    {
        var v = Engine().Inspect(new FirewallRequest("GET", "/api/files", [new("path", "../../etc/passwd")], []));
        AssertBlocked(v, FindingCategory.PathTraversal);
        Assert.Contains(v.Findings, f => f.Detail!.StartsWith("query.path"));
    }

    [Fact]
    public void Command_injection_is_recorded_but_not_blocked_by_default()
    {
        var v = Engine().Inspect(Json("""{ "host": "example.com; curl http://example.com" }"""));
        Assert.True(v.Allowed);
        Assert.Contains(v.Findings, f => f.Category == FindingCategory.CommandInjection);
    }

    [Fact]
    public void Endpoint_can_allow_a_detector()
    {
        Assert.True(Engine().Inspect(Json("""{ "body": "Hello {{ name }}" }""", path: "/templates/welcome")).Allowed);
    }

    [Fact]
    public void Audit_mode_records_but_allows()
    {
        var v = Engine(mode: "audit").Inspect(Json("""{ "source": "reference://x" }"""));
        Assert.True(v.Allowed);
        Assert.Equal(SecurityAction.Block, v.PolicyAction);
        Assert.False(v.Enforced);
    }

    [Fact]
    public void Content_type_and_size_limits()
    {
        var engine = Engine("    - path: /api/strict\n      content_types: [application/json]\n      max_body_bytes: 10\n");
        var wrongType = engine.Inspect(new FirewallRequest("POST", "/api/strict", [],
            [new RequestPart("body", "text/xml", null, "<a/>"u8.ToArray())], "text/xml", 4));
        Assert.Equal(415, wrongType.StatusCode);
        Assert.Equal(413, engine.Inspect(Json("""{ "a": "0123456789" }""", path: "/api/strict")).StatusCode);
    }

    [Fact]
    public void Unsupported_schema_keywords_fail_at_startup()
    {
        Assert.Throws<InvalidOperationException>(() => new SchemaValidator("""{ "type": "object", "oneOf": [] }"""));
    }

    [Fact]
    public void Unknown_detector_names_fail_policy_loading()
    {
        Assert.Throws<InvalidOperationException>(() => PolicyLoader.FromYaml("api_firewall:\n  detectors: { sql_magic: block }\n"));
    }
}

public class FirewallQuarantineTests
{
    [Fact]
    public void Quarantine_wins_over_block_so_the_evidence_is_kept()
    {
        var engine = new FirewallEngine(PolicyLoader.FromYaml("api_firewall:\n  detectors: { template_injection: quarantine }\n"));
        var body = """{ "a": "{{ 7 * 7 }}", "b": "reference://x" }"""u8.ToArray();
        var v = engine.Inspect(new FirewallRequest("POST", "/x", [], [new RequestPart("body", "application/json", null, body)], "application/json", body.Length));
        Assert.Equal(SecurityAction.Quarantine, v.Action);
    }
}
