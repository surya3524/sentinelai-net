using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentinelAI;
using SentinelAI.Policy;
using SentinelAI.Scanners;
using SentinelAI.Tools;

namespace Microsoft.Extensions.DependencyInjection;

public sealed class SentinelOptions
{
    /// <summary>Path to the policy file, relative to the content root (or the app folder outside a host).</summary>
    public string PolicyPath { get; set; } = "sentinel.yaml";

    /// <summary>Takes precedence over <see cref="PolicyPath"/> when set.</summary>
    public SentinelPolicy? Policy { get; set; }

    /// <summary>
    /// When the policy file is missing: true (the default) uses the built-in policy and logs a
    /// warning; false throws at startup.
    /// </summary>
    public bool UseDefaultPolicyWhenMissing { get; set; } = true;

    internal List<Func<IServiceProvider, IAiSecurityScanner>> ExtraScanners { get; } = [];

    /// <summary>Add your own detector alongside the built-in ones.</summary>
    public SentinelOptions AddScanner<T>() where T : class, IAiSecurityScanner
    {
        ExtraScanners.Add(sp => ActivatorUtilities.CreateInstance<T>(sp));
        return this;
    }
}

/// <summary>Returned by <c>AddSentinelAI</c> so integrations can chain their own registrations.</summary>
public sealed class SentinelBuilder(IServiceCollection services)
{
    public IServiceCollection Services { get; } = services;

    /// <summary>Use a custom source for the current user and owner id.</summary>
    public SentinelBuilder AddCallerProvider<T>() where T : class, ISentinelCallerProvider
    {
        Services.Replace(ServiceDescriptor.Singleton<ISentinelCallerProvider, T>());
        return this;
    }

    /// <summary>Decide <c>require_approval</c> tool calls. Without one, they are not executed.</summary>
    public SentinelBuilder AddApprovalHandler<T>() where T : class, IToolApprovalHandler
    {
        Services.Replace(ServiceDescriptor.Singleton<IToolApprovalHandler, T>());
        return this;
    }
}

public static class SentinelServiceCollectionExtensions
{
    /// <summary>
    /// Registers the policy (from sentinel.yaml), the built-in scanners, any http_scanners from
    /// the policy, <see cref="SentinelEngine"/> and <see cref="ToolGuard"/>.
    /// </summary>
    public static SentinelBuilder AddSentinelAI(this IServiceCollection services, Action<SentinelOptions>? configure = null)
    {
        var options = new SentinelOptions();
        configure?.Invoke(options);

        services.TryAddSingleton(sp => LoadPolicy(options, sp));

        services.AddHttpClient(nameof(HttpScanner));
        services.TryAddSingleton<IEnumerable<IAiSecurityScanner>>(sp =>
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

        services.TryAddSingleton(sp => new SentinelEngine(
            sp.GetRequiredService<SentinelPolicy>(), sp.GetRequiredService<IEnumerable<IAiSecurityScanner>>()));
        services.TryAddSingleton(sp => new ToolGuard(sp.GetRequiredService<SentinelPolicy>()));
        services.TryAddSingleton(sp => new SentinelAI.Firewall.FirewallEngine(sp.GetRequiredService<SentinelPolicy>()));
        return new SentinelBuilder(services);
    }

    private static SentinelPolicy LoadPolicy(SentinelOptions options, IServiceProvider sp)
    {
        if (options.Policy is not null) return options.Policy;

        var root = sp.GetService<IHostEnvironment>()?.ContentRootPath ?? AppContext.BaseDirectory;
        var path = Path.IsPathRooted(options.PolicyPath) ? options.PolicyPath : Path.Combine(root, options.PolicyPath);
        if (File.Exists(path)) return PolicyLoader.FromFile(path);

        if (!options.UseDefaultPolicyWhenMissing)
            throw new FileNotFoundException($"SentinelAI policy not found at '{path}'.", path);

        sp.GetService<ILoggerFactory>()?.CreateLogger("SentinelAI").LogWarning(
            "SentinelAI policy not found at {Path}; using the built-in default. All tool calls are blocked until you list your tools in a policy file.",
            path);
        return PolicyLoader.Default();
    }
}
