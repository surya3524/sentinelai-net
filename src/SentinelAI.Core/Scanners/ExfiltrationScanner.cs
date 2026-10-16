using System.Text.RegularExpressions;
using SentinelAI.Policy;

namespace SentinelAI.Scanners;

/// <summary>
/// Blocks model output that would make the client contact a non-allowlisted host
/// carrying data, e.g. a markdown image whose URL query holds conversation content.
/// Rendering such an image leaks data without any click.
/// </summary>
public sealed partial class ExfiltrationScanner(SentinelPolicy policy) : IAiSecurityScanner
{
    private readonly HashSet<string> _allowed = policy.Exfiltration.AllowedDomains
        .Select(d => d.ToLowerInvariant()).ToHashSet();

    public string Name => "exfiltration";

    public bool AppliesTo(ContentSource source) => source is ContentSource.ModelOutput;

    public Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (Match m in MarkdownImage().Matches(context.Content))
            Check(m.Groups["url"].Value, "markdown-image", autoLoads: true, m, findings);
        foreach (Match m in HtmlImage().Matches(context.Content))
            Check(m.Groups["url"].Value, "html-image", autoLoads: true, m, findings);
        foreach (Match m in MarkdownLink().Matches(context.Content))
            Check(m.Groups["url"].Value, "markdown-link", autoLoads: false, m, findings);

        return Task.FromResult(findings.Count == 0 ? SecurityScanResult.Clean(Name) : new SecurityScanResult(Name, findings));
    }

    private void Check(string url, string rule, bool autoLoads, Match m, List<Finding> findings)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
        if (IsAllowed(uri.Host)) return;

        var carriesData = uri.Query.Length > policy.Exfiltration.MaxQueryLength || uri.AbsolutePath.Length > 120;
        if (!autoLoads && !carriesData) return;

        var confidence = autoLoads && carriesData ? 0.97 : autoLoads ? 0.75 : 0.7;
        findings.Add(new Finding(Name, FindingCategory.Exfiltration, rule, confidence, m.Index, m.Length,
            $"untrusted host {uri.Host}" + (carriesData ? " with data in URL" : "")));
    }

    private bool IsAllowed(string host)
    {
        host = host.ToLowerInvariant();
        return _allowed.Any(d => host == d || host.EndsWith("." + d, StringComparison.Ordinal));
    }

    [GeneratedRegex(@"!\[[^\]]*\]\((?<url>[^)\s]+)[^)]*\)")] private static partial Regex MarkdownImage();
    [GeneratedRegex(@"<img[^>]+src\s*=\s*[""'](?<url>[^""']+)[""']", RegexOptions.IgnoreCase)] private static partial Regex HtmlImage();
    [GeneratedRegex(@"(?<!!)\[[^\]]*\]\((?<url>[^)\s]+)[^)]*\)")] private static partial Regex MarkdownLink();
}
