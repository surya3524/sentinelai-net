using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Policy;
using SentinelAI.Scanners;
using SentinelAI.Tools;

namespace SentinelAI.AspNetCore;

public sealed class SentinelOptions
{
    /// <summary>Path to sentinel.yaml, relative to the content root.</summary>
    public string PolicyPath { get; set; } = "sentinel.yaml";

    /// <summary>Takes precedence over <see cref="PolicyPath"/> when set.</summary>
    public SentinelPolicy? Policy { get; set; }

    internal List<Func<IServiceProvider, IAiSecurityScanner>> ExtraScanners { get; } = [];

    /// <summary>Add your own detector alongside the built-in ones.</summary>
    public SentinelOptions AddScanner<T>() where T : class, IAiSecurityScanner
    {
        ExtraScanners.Add(sp => ActivatorUtilities.CreateInstance<T>(sp));
        return this;
    }
}

public static class SentinelServiceCollectionExtensions
{
    /// <summary>
    /// Registers the policy, built-in scanners, any http_scanners from policy,
    /// <see cref="SentinelEngine"/> and <see cref="ToolGuard"/>.
    /// </summary>
    public static IServiceCollection AddSentinelAI(this IServiceCollection services, Action<SentinelOptions>? configure = null)
    {
        var options = new SentinelOptions();
        configure?.Invoke(options);

        services.AddSingleton(sp =>
        {
            if (options.Policy is not null) return options.Policy;
            var env = sp.GetService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>();
            var path = Path.IsPathRooted(options.PolicyPath) || env is null
                ? options.PolicyPath
                : Path.Combine(env.ContentRootPath, options.PolicyPath);
            return PolicyLoader.FromFile(path);
        });

        services.AddHttpClient(nameof(HttpScanner));
        services.AddSingleton<IEnumerable<IAiSecurityScanner>>(sp =>
        {
            var policy = sp.GetRequiredService<SentinelPolicy>();
            var factory = sp.GetRequiredService<IHttpClientFactory>();
            var list = new List<IAiSecurityScanner>
            {
                new RuleScanner(policy),
                new SecretScanner(),
                new PiiScanner(),
                new ExfiltrationScanner(policy),
            };
            list.AddRange(policy.HttpScanners.Select(d => new HttpScanner(d, factory.CreateClient(nameof(HttpScanner)))));
            list.AddRange(options.ExtraScanners.Select(f => f(sp)));
            return list;
        });

        services.AddSingleton(sp => new SentinelEngine(
            sp.GetRequiredService<SentinelPolicy>(), sp.GetRequiredService<IEnumerable<IAiSecurityScanner>>()));
        services.AddSingleton(sp => new ToolGuard(sp.GetRequiredService<SentinelPolicy>()));
        return services;
    }
}
