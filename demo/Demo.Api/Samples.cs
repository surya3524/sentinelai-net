using System.IO.Compression;
using System.Text;

namespace Demo.Api;

/// <summary>A demo upload. Content is inert: probes like {{ 7 * 7 }} stand in where a real attack would put code.</summary>
public sealed record Sample(string Id, string Title, string Kind, string Technique, string FileName, string ContentBase64, bool Editable, string Expected, string Notes);

public static class Samples
{
    private static Sample Text(string id, string title, string kind, string technique, string file, string content, string expected, string notes) =>
        new(id, title, kind, technique, file, Convert.ToBase64String(Encoding.UTF8.GetBytes(content)), true, expected, notes);

    public static readonly IReadOnlyList<Sample> All =
    [
        Text("benign", "Normal dataset config", "benign", "control", "config.yaml",
            """
            name: imdb-reviews
            description: Movie reviews labelled positive or negative.
            data_files:
              - path: data/train.parquet
                split: train
                offset: 0
                length: 25000
              - path: data/test.parquet
                split: test
            """, "allow", "A legitimate upload. It must pass."),

        Text("hf-template", "Template hidden in a numeric field", "attack", "template injection (the Hugging Face pattern)", "config.yaml",
            """
            name: imdb-reviews
            data_files:
              - path: data/train.parquet
                offset: "{{ 7 * 7 }}"
            """, "block", "A real attacker puts code where {{ 7 * 7 }} is. The schema says offset is an integer, and the template detector flags it too."),

        Text("reference-spec", "fsspec reference:// spec", "attack", "dangerous URL scheme", "config.yaml",
            """
            name: imdb-reviews
            data_files:
              - path: "reference://"
                offset: 0
            """, "block", "A reference spec makes the loader follow uploader-controlled references."),

        Text("ssrf", "Data file pointing at cloud metadata", "attack", "SSRF", "config.yaml",
            """
            name: imdb-reviews
            data_files:
              - path: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            """, "block", "Fetching this from inside the cloud returns the worker's credentials."),

        Text("traversal", "Path that climbs out of the dataset", "attack", "path traversal", "config.yaml",
            """
            name: imdb-reviews
            data_files:
              - path: "../../../etc/passwd"
            """, "block", "Reads a file outside the dataset folder."),

        Text("yaml-tag", "YAML object tag", "attack", "unsafe deserialization", "config.yaml",
            """
            name: imdb-reviews
            data_files: []
            loader: !!python/object:datetime.date {}
            """, "block", "With an unsafe loader, tags like this construct arbitrary objects. The object here is harmless; attackers pick ones that run commands."),

        Text("base64", "Template smuggled in base64", "attack", "encoding evasion", "config.yaml",
            $"""
            name: imdb-reviews
            description: {Convert.ToBase64String(Encoding.UTF8.GetBytes("offset = {{ 7 * 7 }}"))}
            data_files:
              - path: data/train.parquet
            """, "block", "The payload is hidden in base64. SentinelAI decodes it and inspects what's inside."),

        Text("json-type", "Polymorphic type hint in JSON", "attack", "unsafe deserialization", "config.json",
            """
            {
              "name": "imdb-reviews",
              "data_files": [ { "path": "data/train.parquet" } ],
              "loader": { "$type": "Some.Loader, SomeAssembly" }
            }
            """, "block", "Serializers that honour $type create whatever type the uploader names."),

        new("zip-slip", "Zip archive with an escaping entry", "attack", "zip slip + nested payload", "bundle.zip", Zip(), false, "block",
            "The archive holds a config with a template and an entry named ../../worker/startup.sh that would be written outside the extraction folder."),
    ];

    private static string Zip()
    {
        var buffer = new MemoryStream();
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            using (var w = new StreamWriter(archive.CreateEntry("config.yaml").Open()))
                w.Write("name: imdb-reviews\ndata_files:\n  - path: data/train.parquet\n    offset: \"{{ 7 * 7 }}\"\n");
            using (var w = new StreamWriter(archive.CreateEntry("../../worker/startup.sh").Open()))
                w.Write("# placeholder: this file is harmless\n");
        }
        return Convert.ToBase64String(buffer.ToArray());
    }
}
