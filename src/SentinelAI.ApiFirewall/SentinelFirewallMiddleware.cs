using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using SentinelAI.Firewall;

namespace SentinelAI.ApiFirewall;

public sealed class SentinelFirewallOptions
{
    /// <summary>Decide per request whether to inspect it. Defaults to every request with an endpoint or a body.</summary>
    public Func<HttpContext, bool>? ShouldInspect { get; set; }
}

/// <summary>Endpoint metadata that turns the firewall off, e.g. for health checks.</summary>
public sealed class SkipSentinelFirewallMetadata;

/// <summary>Stores blocked requests for later review.</summary>
public interface IQuarantineStore
{
    Task SaveAsync(QuarantinedRequest request, CancellationToken cancellationToken);
}

public sealed record QuarantinedRequest(
    string Id, DateTimeOffset At, string Method, string Path, string? ClientAddress,
    string Reason, IReadOnlyList<Finding> Findings, IReadOnlyList<RequestPart> Parts);

/// <summary>Writes each quarantined request to its own folder: meta.json plus the original parts.</summary>
public sealed class FileQuarantineStore(string root) : IQuarantineStore
{
    public string Root { get; } = root;

    public async Task SaveAsync(QuarantinedRequest request, CancellationToken cancellationToken)
    {
        var dir = Path.Combine(Root, request.At.ToString("yyyyMMdd"), request.Id);
        Directory.CreateDirectory(dir);
        var parts = new List<object>();
        for (var i = 0; i < request.Parts.Count; i++)
        {
            var p = request.Parts[i];
            var file = $"part{i}.bin"; // never trust the uploaded name on disk
            await File.WriteAllBytesAsync(Path.Combine(dir, file), p.Content.ToArray(), cancellationToken);
            parts.Add(new { file, location = p.Location, contentType = p.ContentType, originalName = p.FileName, bytes = p.Content.Length });
        }
        var meta = new { request.Id, request.At, request.Method, request.Path, request.ClientAddress, request.Reason, request.Findings, parts };
        await File.WriteAllTextAsync(Path.Combine(dir, "meta.json"),
            JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }), cancellationToken);
    }
}

/// <summary>
/// Reads each request (body, form fields, uploaded files), runs <see cref="FirewallEngine"/> on it, and
/// rejects it before the endpoint runs if policy says so. The body is buffered and rewound, so
/// endpoints read it as normal.
/// </summary>
public sealed class SentinelFirewallMiddleware(
    RequestDelegate next,
    FirewallEngine engine,
    SentinelFirewallOptions options,
    IServiceProvider services,
    ILogger<SentinelFirewallMiddleware> logger)
{
    private IQuarantineStore? _store;

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SkipSentinelFirewallMetadata>() is not null
            || options.ShouldInspect?.Invoke(context) == false)
        {
            await next(context);
            return;
        }

        var request = context.Request;
        var limit = engine.MaxBodyBytes(request.Method, request.Path);
        if (request.ContentLength > limit)
        {
            await Reject(context, engine.Inspect(new FirewallRequest(request.Method, request.Path, [], [], request.ContentType, request.ContentLength.Value)), []);
            return;
        }

        var (parts, length) = await ReadAsync(request, limit, context.RequestAborted);
        var query = request.Query.SelectMany(q => q.Value.Select(v => new KeyValuePair<string, string>(q.Key, v ?? ""))).ToList();
        var verdict = engine.Inspect(new FirewallRequest(request.Method, request.Path, query, parts, request.ContentType, length));

        Activity.Current?.SetTag("sentinel.firewall.action", verdict.Action.ToString().ToLowerInvariant());
        if (verdict.Findings.Count > 0)
            logger.LogWarning("SentinelAI firewall {Action} {Method} {Path}: {Reason}",
                verdict.Enforced ? verdict.Action : $"would {verdict.PolicyAction}", request.Method, request.Path, verdict.Reason);

        if (verdict.Allowed)
        {
            if (request.Body.CanSeek) request.Body.Position = 0;
            await next(context);
            return;
        }
        await Reject(context, verdict, parts);
    }

    private async Task<(List<RequestPart> Parts, long Length)> ReadAsync(HttpRequest request, long limit, CancellationToken ct)
    {
        var parts = new List<RequestPart>();
        if (request.ContentLength is 0 || (request.ContentLength is null && !HttpMethods.IsPost(request.Method)
            && !HttpMethods.IsPut(request.Method) && !HttpMethods.IsPatch(request.Method)))
            return (parts, 0);

        request.EnableBuffering(bufferThreshold: 64 * 1024, bufferLimit: limit + 1);
        var buffer = new MemoryStream();
        try
        {
            await request.Body.CopyToAsync(buffer, ct);
        }
        catch (IOException)
        {
            return (parts, limit + 1); // buffer limit exceeded: reported as too large
        }
        request.Body.Position = 0;
        var body = buffer.ToArray();
        if (body.Length == 0) return (parts, 0);
        if (body.Length > limit) return (parts, body.Length);

        var type = request.ContentType ?? "";
        if (MediaTypeHeaderValue.TryParse(type, out var media) && media.MediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
        {
            var boundary = HeaderUtilities.RemoveQuotes(media.Boundary).Value;
            if (!string.IsNullOrEmpty(boundary))
            {
                var reader = new MultipartReader(boundary, new MemoryStream(body));
                while (await reader.ReadNextSectionAsync(ct) is { } section)
                {
                    var data = new MemoryStream();
                    await section.Body.CopyToAsync(data, ct);
                    ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out var disposition);
                    var name = disposition is null ? "part" : HeaderUtilities.RemoveQuotes(disposition.Name).Value ?? "part";
                    var rawFileName = disposition is null ? default
                        : disposition.FileNameStar.HasValue ? disposition.FileNameStar : disposition.FileName;
                    var fileName = HeaderUtilities.RemoveQuotes(rawFileName).Value;
                    parts.Add(string.IsNullOrEmpty(fileName)
                        ? new RequestPart($"form.{name}", section.ContentType ?? "text/plain", null, data.ToArray())
                        : new RequestPart($"file:{fileName}", section.ContentType, fileName, data.ToArray(), IsUpload: true));
                }
                return (parts, body.Length);
            }
        }
        if (type.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var (key, values) in QueryHelpers.ParseQuery(Encoding.UTF8.GetString(body)))
                foreach (var v in values)
                    parts.Add(new RequestPart($"form.{key}", "text/plain", null, Encoding.UTF8.GetBytes(v ?? "")));
            return (parts, body.Length);
        }

        parts.Add(new RequestPart("body", type, null, body));
        return (parts, body.Length);
    }

    private async Task Reject(HttpContext context, FirewallVerdict verdict, IReadOnlyList<RequestPart> parts)
    {
        var id = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier;
        if (verdict.Action == SecurityAction.Quarantine)
        {
            try
            {
                await Store().SaveAsync(new QuarantinedRequest(id, DateTimeOffset.UtcNow, context.Request.Method, context.Request.Path,
                    context.Connection.RemoteIpAddress?.ToString(), verdict.Reason, verdict.Findings, parts), context.RequestAborted);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                logger.LogError(ex, "SentinelAI could not quarantine request {Id}", id);
            }
        }

        var expose = engine.Policy.ExposeDetails;
        var problem = new Dictionary<string, object?>
        {
            ["type"] = "https://sentinelaidotnet.com/errors/request-blocked",
            ["title"] = verdict.StatusCode switch
            {
                413 => "Request too large",
                415 => "Unsupported content type",
                _ => verdict.Action == SecurityAction.Quarantine ? "Request held for review" : "Request blocked by security policy",
            },
            ["status"] = verdict.StatusCode,
            ["detail"] = expose ? verdict.Reason : "The request contained content that is not allowed.",
            ["traceId"] = id,
        };
        if (expose)
            problem["findings"] = verdict.Findings.Select(f => new { category = f.Category, rule = f.Rule, location = f.Detail }).ToList();

        context.Response.StatusCode = verdict.StatusCode;
        context.Response.ContentType = "application/problem+json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(problem), context.RequestAborted);
    }

    private IQuarantineStore Store()
    {
        if (_store is not null) return _store;
        var root = engine.Policy.QuarantinePath;
        if (!Path.IsPathRooted(root))
            root = Path.Combine(services.GetService<IWebHostEnvironment>()?.ContentRootPath ?? AppContext.BaseDirectory, root);
        return _store = services.GetService<IQuarantineStore>() ?? new FileQuarantineStore(root);
    }
}

public static class SentinelFirewallExtensions
{
    /// <summary>
    /// Inspects every request against the <c>api_firewall</c> section of sentinel.yaml.
    /// Requires <c>services.AddSentinelAI()</c>. Place it early, after authentication if you
    /// want blocked requests attributed to a user.
    /// </summary>
    public static IApplicationBuilder UseSentinelFirewall(this IApplicationBuilder app, Action<SentinelFirewallOptions>? configure = null)
    {
        var options = new SentinelFirewallOptions();
        configure?.Invoke(options);
        if (app.ApplicationServices.GetService<FirewallEngine>() is null)
            throw new InvalidOperationException("SentinelAI is not registered. Call services.AddSentinelAI().");
        return app.UseMiddleware<SentinelFirewallMiddleware>(options);
    }

    /// <summary>Turn the firewall off for this endpoint.</summary>
    public static TBuilder SkipSentinelFirewall<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(new SkipSentinelFirewallMetadata());
}
