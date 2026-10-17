using Microsoft.Extensions.DependencyInjection;
using SentinelAI;
using SentinelAI.Extensions.AI;
using SentinelAI.Tools;

namespace Microsoft.Extensions.AI;

public static class SentinelChatClientBuilderExtensions
{
    /// <summary>
    /// Adds SentinelAI policy enforcement. Requires <c>services.AddSentinelAI()</c>.
    /// Call it <b>before</b> <c>UseFunctionInvocation()</c> so each tool call is authorized as it runs:
    /// <code>
    /// builder.Services.AddChatClient(client)
    ///     .UseSentinel()
    ///     .UseFunctionInvocation();
    /// </code>
    /// </summary>
    public static ChatClientBuilder UseSentinel(this ChatClientBuilder builder, Action<SentinelChatClientOptions>? configure = null)
    {
        var options = new SentinelChatClientOptions();
        configure?.Invoke(options);

        return builder.Use((inner, services) => new SentinelChatClient(
            inner,
            services.GetService<SentinelEngine>() ?? throw new InvalidOperationException(
                "SentinelAI is not registered. Call services.AddSentinelAI() and build the chat client with the app's service provider."),
            services.GetRequiredService<ToolGuard>(),
            options,
            services.GetService<ISentinelCallerProvider>(),
            services.GetService<IToolApprovalHandler>()));
    }
}
