using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SentinelAI.Tools;

namespace SentinelAI.AspNetCore;

public sealed class HttpContextCallerOptions
{
    /// <summary>Claims tried in order for the user id.</summary>
    public string[] UserIdClaims { get; set; } = [ClaimTypes.NameIdentifier, "sub"];

    /// <summary>
    /// Claims tried in order for the owner id that ownership-checked tools compare against
    /// (for example "customer_id" or "tenant_id"). Empty means the user id is the owner id.
    /// </summary>
    public string[] OwnerIdClaims { get; set; } = [];

    public string? AgentId { get; set; }
}

/// <summary>Reads the caller from the signed-in user of the current request.</summary>
public sealed class HttpContextCallerProvider(IHttpContextAccessor accessor, IOptions<HttpContextCallerOptions> options) : ISentinelCallerProvider
{
    public SentinelCaller? GetCurrentCaller()
    {
        var user = accessor.HttpContext?.User;
        if (user?.Identity?.IsAuthenticated != true) return null;

        string? Find(IEnumerable<string> types) =>
            types.Select(t => user.FindFirst(t)?.Value).FirstOrDefault(v => !string.IsNullOrEmpty(v));

        var o = options.Value;
        var userId = Find(o.UserIdClaims) ?? user.Identity.Name;
        if (userId is null) return null;
        var ownerId = o.OwnerIdClaims.Length == 0 ? userId : Find(o.OwnerIdClaims);
        return new SentinelCaller(userId, ownerId, o.AgentId);
    }
}

public static class SentinelAspNetCoreExtensions
{
    /// <summary>Take the caller for tool authorization from the signed-in user's claims.</summary>
    public static SentinelBuilder AddHttpContextCaller(this SentinelBuilder builder, Action<HttpContextCallerOptions>? configure = null)
    {
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddOptions<HttpContextCallerOptions>();
        if (configure is not null) builder.Services.Configure(configure);
        return builder.AddCallerProvider<HttpContextCallerProvider>();
    }

    /// <summary>
    /// Scans text from the request body before the handler runs and returns 400 if policy blocks it.
    /// For endpoints that take a prompt without going through an IChatClient.
    /// <code>app.MapPost("/ask", handler).ScanWithSentinel&lt;AskRequest&gt;(r =&gt; r.Question);</code>
    /// </summary>
    public static RouteHandlerBuilder ScanWithSentinel<TRequest>(this RouteHandlerBuilder builder, Func<TRequest, string?> selectText)
    {
        return builder.AddEndpointFilter(async (ctx, next) =>
        {
            var request = ctx.Arguments.OfType<TRequest>().FirstOrDefault();
            var text = request is null ? null : selectText(request);
            if (string.IsNullOrWhiteSpace(text)) return await next(ctx);

            var services = ctx.HttpContext.RequestServices;
            var engine = services.GetService<SentinelEngine>()
                ?? throw new InvalidOperationException("SentinelAI is not registered. Call services.AddSentinelAI().");
            var caller = services.GetService<ISentinelCallerProvider>()?.GetCurrentCaller();

            var decision = await engine.ScanAsync(new SecurityScanContext(ContentSource.UserInput, text,
                caller?.UserId, caller?.AgentId, ctx.HttpContext.Request.Path), ctx.HttpContext.RequestAborted);

            return decision.Action == SecurityAction.Block
                ? Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Request blocked by security policy", detail: decision.Reason)
                : await next(ctx);
        });
    }
}
