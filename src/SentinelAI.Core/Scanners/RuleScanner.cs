using System.Text.RegularExpressions;
using SentinelAI.Policy;

namespace SentinelAI.Scanners;

/// <summary>
/// Configurable regex rules from policy, evaluated on normalized text. Independent rule
/// weights combine as 1 - Π(1 - w), so several weak signals can add up to a confident one.
/// Also flags hidden Unicode, which has no legitimate use in most chat input.
/// </summary>
public sealed class RuleScanner : IAiSecurityScanner
{
    private readonly IReadOnlyList<(RuleDefinition Def, Regex Regex, HashSet<ContentSource> Sources)> _rules;
    private readonly double _hiddenUnicodeWeight;

    public RuleScanner(SentinelPolicy policy)
    {
        _rules = policy.Rules.Select(r => (
            r,
            new Regex(r.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250)),
            r.Sources.Count == 0
                ? Enum.GetValues<ContentSource>().ToHashSet()
                : r.Sources.Select(PolicyLoader.ParseSource).ToHashSet())).ToList();
        _hiddenUnicodeWeight = policy.PromptInjection.HiddenUnicodeWeight;
    }

    public string Name => "rules";

    public bool AppliesTo(ContentSource source) => source is ContentSource.UserInput or ContentSource.RetrievedDocument;

    public Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken)
    {
        var normalized = TextNormalizer.Normalize(context.Content);
        var findings = new List<Finding>();
        var miss = 1.0;

        if (normalized.InvisibleCharCount > 0 && _hiddenUnicodeWeight > 0)
        {
            miss *= 1 - _hiddenUnicodeWeight;
            findings.Add(new Finding(Name, FindingCategory.PromptInjection, "hidden-unicode", _hiddenUnicodeWeight,
                Detail: $"{normalized.InvisibleCharCount} invisible character(s)" +
                        (normalized.DecodedTagText is null ? "" : "; tag characters decoded and rescanned")));
        }

        foreach (var (def, regex, sources) in _rules)
        {
            if (!sources.Contains(context.Source)) continue;
            try
            {
                if (regex.IsMatch(normalized.Text))
                {
                    miss *= 1 - def.Weight;
                    findings.Add(new Finding(Name, FindingCategory.PromptInjection, def.Id, def.Weight, Detail: def.Description));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                findings.Add(new Finding(Name, FindingCategory.PromptInjection, def.Id + ":timeout", 0.5, Detail: "rule timed out"));
                miss *= 0.5;
            }
        }

        if (findings.Count == 0) return Task.FromResult(SecurityScanResult.Clean(Name));

        // Report the combined score as a summary finding so policy thresholds see one number.
        var combined = Math.Round(1 - miss, 3);
        findings.Add(new Finding(Name, FindingCategory.PromptInjection, "combined-score", combined));
        return Task.FromResult(new SecurityScanResult(Name, findings));
    }
}
