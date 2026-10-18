using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace SentinelAI.Firewall;

/// <summary>A value found in a request: its location (e.g. <c>file:config.yaml.data_files[0].offset</c>) and text.</summary>
public readonly record struct RequestValue(string Location, string Text, bool IsKey = false);

/// <summary>Inspects one value. Detectors only report; policy decides what happens.</summary>
public interface IRequestDetector
{
    string Category { get; }
    void Inspect(RequestValue value, List<Finding> findings);
}

internal static class Hit
{
    public static Finding Make(string category, string rule, double confidence, RequestValue v, string? note = null) =>
        new("api_firewall", category, rule, confidence, Detail: note is null ? v.Location : $"{v.Location}: {note}");
}

/// <summary>
/// Template expressions (Jinja/Twig/Liquid, ERB, ${...} expression languages). Data that a server
/// later renders as a template runs as code: the root of server-side template injection.
/// </summary>
public sealed partial class TemplateInjectionDetector : IRequestDetector
{
    public string Category => FindingCategory.TemplateInjection;

    public void Inspect(RequestValue v, List<Finding> findings)
    {
        var t = v.Text;
        if (t.Length < 4) return;
        if (JinjaStatement().IsMatch(t)) findings.Add(Hit.Make(Category, "jinja-statement", 0.95, v));
        else if (JinjaExpression().IsMatch(t)) findings.Add(Hit.Make(Category, "jinja-expression", 0.9, v));
        if (Erb().IsMatch(t)) findings.Add(Hit.Make(Category, "erb-expression", 0.9, v));
        if (JndiLookup().IsMatch(t)) findings.Add(Hit.Make(Category, "jndi-lookup", 0.99, v));
        else if (ExpressionLanguage().IsMatch(t)) findings.Add(Hit.Make(Category, "expression-language", 0.8, v));
    }

    [GeneratedRegex(@"\{%-?.{1,500}?-?%\}", RegexOptions.Singleline)] private static partial Regex JinjaStatement();
    [GeneratedRegex(@"\{\{-?.{1,500}?-?\}\}", RegexOptions.Singleline)] private static partial Regex JinjaExpression();
    [GeneratedRegex(@"<%[=-]?.{1,500}?%>", RegexOptions.Singleline)] private static partial Regex Erb();
    [GeneratedRegex(@"\$\{\s*(jndi|ctx|env|sys|java|script|lower|upper)\s*:", RegexOptions.IgnoreCase)] private static partial Regex JndiLookup();
    [GeneratedRegex(@"[$#]\{[^}\r\n]{1,200}\}")] private static partial Regex ExpressionLanguage();
}

/// <summary>
/// Markers that make a parser build arbitrary objects: YAML language tags, type-hint keys used by
/// polymorphic JSON serializers, and serialized-object headers (Java, .NET BinaryFormatter, pickle).
/// </summary>
public sealed partial class UnsafeDeserializationDetector : IRequestDetector
{
    private static readonly HashSet<string> TypeHintKeys = new(StringComparer.Ordinal)
    {
        "$type", "@type", "@class", "__class__", "__reduce__", "py/object", "py/reduce", "!!python/object", "javaClass",
    };

    public string Category => FindingCategory.UnsafeDeserialization;

    public void Inspect(RequestValue v, List<Finding> findings)
    {
        if (v.IsKey)
        {
            if (TypeHintKeys.Contains(v.Text)) findings.Add(Hit.Make(Category, "type-hint-key", 0.9, v, $"key '{v.Text}'"));
            return;
        }
        if (LanguageTag().IsMatch(v.Text)) findings.Add(Hit.Make(Category, "yaml-language-tag", 0.97, v));
    }

    /// <summary>Called by the payload walker with decoded binary content.</summary>
    public void InspectBytes(ReadOnlySpan<byte> b, RequestValue v, List<Finding> findings)
    {
        if (b.Length >= 4 && b[0] == 0xAC && b[1] == 0xED && b[2] == 0x00 && b[3] == 0x05)
            findings.Add(Hit.Make(Category, "java-serialized-object", 0.97, v));
        else if (b.Length >= 9 && b[0] == 0x00 && b[1] == 0x01 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0xFF && b[6] == 0xFF && b[7] == 0xFF && b[8] == 0xFF)
            findings.Add(Hit.Make(Category, "dotnet-binaryformatter", 0.97, v));
        else if (b.Length >= 2 && b[0] == 0x80 && b[1] is >= 2 and <= 5)
            findings.Add(Hit.Make(Category, "python-pickle", 0.9, v));
    }

    /// <summary>A YAML node tag found while parsing (anything outside the YAML core schema).</summary>
    public static Finding YamlTag(string tag, RequestValue v)
    {
        var language = tag.Contains("python", StringComparison.OrdinalIgnoreCase) || tag.Contains("ruby", StringComparison.OrdinalIgnoreCase)
            || tag.Contains("java", StringComparison.OrdinalIgnoreCase) || tag.Contains("perl", StringComparison.OrdinalIgnoreCase);
        return Hit.Make(FindingCategory.UnsafeDeserialization, language ? "yaml-language-tag" : "yaml-custom-tag", language ? 0.99 : 0.85, v, $"tag {tag}");
    }

    [GeneratedRegex(@"!!(python|ruby|java|perl|php)/|tag:yaml\.org,2002:(python|ruby|java|perl)", RegexOptions.IgnoreCase)]
    private static partial Regex LanguageTag();
}

/// <summary>
/// URLs inside request data that a server-side component might open: non-web schemes
/// (file, gopher, reference, jar…) and web URLs aimed at internal networks or cloud metadata
/// (server-side request forgery). Only literal hosts are checked; DNS is not resolved.
/// </summary>
public sealed partial class DangerousUrlDetector(UrlPolicy policy) : IRequestDetector
{
    private static readonly string[] InternalNames = ["localhost", "metadata", "metadata.google.internal", "instance-data"];
    private readonly HashSet<string> _schemes = policy.AllowedSchemes.Select(s => s.ToLowerInvariant()).ToHashSet();
    private readonly HashSet<string> _hosts = policy.AllowedHosts.Select(h => h.ToLowerInvariant()).ToHashSet();

    public string Category => FindingCategory.DangerousUrl;

    public void Inspect(RequestValue v, List<Finding> findings)
    {
        foreach (Match m in SchemeUrl().Matches(v.Text))
        {
            var scheme = m.Groups["scheme"].Value.ToLowerInvariant();
            if (!_schemes.Contains(scheme))
            {
                findings.Add(Hit.Make(Category, "disallowed-scheme", 0.95, v, $"{scheme}:// URL"));
                continue;
            }
            if (!policy.BlockPrivateNetworks) continue;
            if (!Uri.TryCreate(m.Value, UriKind.Absolute, out var uri)) continue;
            var host = uri.IdnHost.Trim('[', ']').ToLowerInvariant();
            if (_hosts.Contains(host)) continue;
            if (IsInternal(host)) findings.Add(Hit.Make(Category, "internal-address", 0.9, v, $"{scheme} URL to internal host {host}"));
        }
    }

    internal static bool IsInternal(string host)
    {
        if (InternalNames.Contains(host) || host.EndsWith(".localhost", StringComparison.Ordinal)
            || host.EndsWith(".internal", StringComparison.Ordinal) || host.EndsWith(".local", StringComparison.Ordinal))
            return true;
        if (!IPAddress.TryParse(host, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || (ip.GetAddressBytes()[0] & 0xFE) == 0xFC; // fc00::/7
        var b = ip.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] is >= 16 and <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)           // link-local, including cloud metadata 169.254.169.254
            || (b[0] == 100 && b[1] is >= 64 and <= 127) // carrier-grade NAT
            || b[0] == 0 || b[0] == 127;
    }

    [GeneratedRegex(@"(?<scheme>[a-zA-Z][a-zA-Z0-9+.\-]{1,30})://[^\s""'<>]*")] private static partial Regex SchemeUrl();
}

/// <summary>Paths that climb out of their directory, null bytes, and absolute paths to system locations.</summary>
public sealed partial class PathTraversalDetector : IRequestDetector
{
    public string Category => FindingCategory.PathTraversal;

    public void Inspect(RequestValue v, List<Finding> findings)
    {
        if (v.IsKey) return;
        var t = v.Text;
        if (Climb().IsMatch(t)) findings.Add(Hit.Make(Category, "dot-dot-segment", 0.85, v));
        if (t.Contains('\0')) findings.Add(Hit.Make(Category, "null-byte", 0.8, v));
        if (SystemPath().IsMatch(t)) findings.Add(Hit.Make(Category, "system-path", 0.75, v));
    }

    // "../" at the start of the value or right after a separator, "=" or ":": positions where it acts as a path.
    [GeneratedRegex(@"(^|[\\/=:])\.\.[\\/]")] private static partial Regex Climb();
    [GeneratedRegex(@"^\s*(/etc/|/proc/|/root/|/var/run/|~/\.ssh|[a-zA-Z]:\\(windows|users)\\)", RegexOptions.IgnoreCase)] private static partial Regex SystemPath();
}

/// <summary>Shell command chaining and substitution. Recorded only by default: legitimate text trips it more often.</summary>
public sealed partial class CommandInjectionDetector : IRequestDetector
{
    public string Category => FindingCategory.CommandInjection;

    public void Inspect(RequestValue v, List<Finding> findings)
    {
        if (v.IsKey) return;
        if (Chained().IsMatch(v.Text)) findings.Add(Hit.Make(Category, "chained-command", 0.7, v));
        if (Substitution().IsMatch(v.Text)) findings.Add(Hit.Make(Category, "command-substitution", 0.6, v));
    }

    [GeneratedRegex(@"(;|&&|\|\|?)\s*(curl|wget|bash|sh|zsh|nc|ncat|python3?|perl|powershell|pwsh|cmd)(\.exe)?(\s|$)", RegexOptions.IgnoreCase)]
    private static partial Regex Chained();
    [GeneratedRegex(@"\$\([^)\r\n]{1,100}\)")] private static partial Regex Substitution();
}
