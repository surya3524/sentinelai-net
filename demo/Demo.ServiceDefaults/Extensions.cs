using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Microsoft.Extensions.Hosting;

/// <summary>OpenTelemetry and health checks shared by Aspire services.</summary>
public static class Extensions
{
    // Kept as strings so this project does not depend on SentinelAI.
    private static readonly string[] Sources = ["SentinelAI", "Demo.Agent"];

    public static TBuilder AddServiceDefaults<TBuilder>(this TBuilder builder) where TBuilder : IHostApplicationBuilder
    {
        builder.Logging.AddOpenTelemetry(l =>
        {
            l.IncludeFormattedMessage = true;
            l.IncludeScopes = true;
        });

        builder.Services.AddOpenTelemetry()
            .WithMetrics(m => m
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation()
                .AddMeter(Sources))
            .WithTracing(t => t
                .AddSource(builder.Environment.ApplicationName)
                .AddSource(Sources)
                // Trace actions only: skip static files, the event stream and UI polling.
                .AddAspNetCoreInstrumentation(o => o.Filter = ctx =>
                    ctx.Request.Path.StartsWithSegments("/api") &&
                    !ctx.Request.Path.StartsWithSegments("/api/events") &&
                    !HttpMethods.IsGet(ctx.Request.Method))
                .AddHttpClientInstrumentation());

        // Aspire sets this; when run standalone, telemetry stays in-process.
        if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
            builder.Services.AddOpenTelemetry().UseOtlpExporter();

        builder.Services.AddHealthChecks().AddCheck("self", () => HealthCheckResult.Healthy(), ["live"]);
        return builder;
    }

    public static WebApplication MapDefaultEndpoints(this WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.MapHealthChecks("/health");
            app.MapHealthChecks("/alive", new HealthCheckOptions { Predicate = r => r.Tags.Contains("live") });
        }
        return app;
    }
}
