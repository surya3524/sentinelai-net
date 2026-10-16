using System.Text.RegularExpressions;

namespace SentinelAI.Scanners;

/// <summary>
/// Lightweight PII detection (email, phone, US SSN, payment cards with a Luhn check).
/// For production, plug in Microsoft Presidio through <see cref="HttpScanner"/>.
/// </summary>
public sealed partial class PiiScanner : IAiSecurityScanner
{
    public string Name => "pii";

    public bool AppliesTo(ContentSource source) => source is ContentSource.ModelOutput;

    public Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken)
    {
        var text = context.Content;
        var findings = new List<Finding>();

        foreach (Match m in Email().Matches(text)) findings.Add(new(Name, FindingCategory.Pii, "email", 0.9, m.Index, m.Length));
        foreach (Match m in Phone().Matches(text)) findings.Add(new(Name, FindingCategory.Pii, "phone", 0.8, m.Index, m.Length));
        foreach (Match m in Ssn().Matches(text)) findings.Add(new(Name, FindingCategory.Pii, "us-ssn", 0.9, m.Index, m.Length));
        foreach (Match m in Card().Matches(text))
        {
            var digits = new string(m.Value.Where(char.IsDigit).ToArray());
            if (digits.Length is >= 13 and <= 19 && Luhn(digits))
                findings.Add(new(Name, FindingCategory.Pii, "payment-card", 0.95, m.Index, m.Length));
        }

        return Task.FromResult(findings.Count == 0 ? SecurityScanResult.Clean(Name) : new SecurityScanResult(Name, findings));
    }

    internal static bool Luhn(string digits)
    {
        var sum = 0;
        var alt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var d = digits[i] - '0';
            if (alt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            alt = !alt;
        }
        return sum % 10 == 0;
    }

    [GeneratedRegex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")] private static partial Regex Email();
    [GeneratedRegex(@"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")] private static partial Regex Phone();
    [GeneratedRegex(@"\b\d{3}-\d{2}-\d{4}\b")] private static partial Regex Ssn();
    [GeneratedRegex(@"\b(?:\d[ -]?){13,19}\b")] private static partial Regex Card();
}
