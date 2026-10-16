using System.Net.Http.Json;
using SentinelAI.Policy;

namespace SentinelAI.Scanners;

/// <summary>
/// Calls an external detector over HTTP so any model (PromptGuard, LlamaFirewall,
/// Presidio, a fine-tuned classifier) can sit behind SentinelAI policy.
///
/// Request:  POST { "source": "user_input", "content": "..." }
/// Response: { "score": 0.0-1.0, "label": "injection", "category": "prompt_injection" }
///
/// Fails open with a low-confidence finding so an outage is visible in telemetry
/// without taking the app down. Set FailClosed to block instead.
/// </summary>
public sealed class HttpScanner(HttpScannerDefinition definition, HttpClient http) : IAiSecurityScanner
{
    private readonly HashSet<ContentSource> _sources = definition.Sources.Count == 0
        ? [ContentSource.UserInput, ContentSource.RetrievedDocument]
        : definition.Sources.Select(PolicyLoader.ParseSource).ToHashSet();

    public string Name => definition.Name;

    public bool AppliesTo(ContentSource source) => _sources.Contains(source);

    public async Task<SecurityScanResult> ScanAsync(SecurityScanContext context, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(definition.TimeoutMs));
        try
        {
            var response = await http.PostAsJsonAsync(definition.Url,
                new { source = PolicyLoader.FormatSource(context.Source), content = context.Content }, cts.Token);
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadFromJsonAsync<Response>(cts.Token);
            if (body is null || body.Score <= 0) return SecurityScanResult.Clean(Name);
            return new SecurityScanResult(Name,
                [new Finding(Name, body.Category ?? FindingCategory.PromptInjection, body.Label ?? "external", body.Score)]);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            var confidence = definition.FailClosed ? 1.0 : 0.0;
            return new SecurityScanResult(Name,
                [new Finding(Name, FindingCategory.PromptInjection, "scanner-unavailable", confidence, Detail: ex.GetType().Name)]);
        }
    }

    private sealed record Response(double Score, string? Label, string? Category);
}
