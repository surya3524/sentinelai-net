using System.Text.RegularExpressions;

namespace SentinelAI.Scanners;

/// <summary>Finds credentials so they can be redacted before they leave the app.</summary>
public sealed partial class SecretScanner : IAiSecurityScanner
{
    private static readonly (string Rule, Regex Regex, int Group)[] Patterns =
    [
        ("aws-access-key-id", AwsKey(), 0),
        ("private-key-block", PrivateKey(), 0),
        ("jwt", Jwt(), 0),
        ("connection-string-password", ConnStringPassword(), 1),
        ("credential-assignment", Assignment(), 2),
        ("bearer-token", Bearer(), 1),
    ];

    public string Name => "secrets";

    public bool AppliesTo(ContentSource source) => source is ContentSource.ModelOutput or ContentSource.UserInput or ContentSource.ToolCall;

    public Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        foreach (var (rule, regex, group) in Patterns)
        {
            foreach (Match m in regex.Matches(context.Content))
            {
                var g = m.Groups[group];
                if (!g.Success || g.Length == 0) continue;
                findings.Add(new Finding(Name, FindingCategory.Secret, rule, 0.95, g.Index, g.Length));
            }
        }
        return Task.FromResult(findings.Count == 0 ? SecurityScanResult.Clean(Name) : new SecurityScanResult(Name, findings));
    }

    [GeneratedRegex(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")] private static partial Regex AwsKey();
    [GeneratedRegex(@"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")] private static partial Regex PrivateKey();
    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")] private static partial Regex Jwt();
    [GeneratedRegex(@"(?i)\b(?:password|pwd)\s*=\s*([^;""'\s]+)")] private static partial Regex ConnStringPassword();
    [GeneratedRegex(@"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret)\b[""']?\s*[:=]\s*[""']?([A-Za-z0-9_\-./+=]{12,})")] private static partial Regex Assignment();
    [GeneratedRegex(@"(?i)\bbearer\s+([A-Za-z0-9_\-.=]{20,})")] private static partial Regex Bearer();
}
