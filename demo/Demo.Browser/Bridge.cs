using System.Text.Json;
using Demo.Agent;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace Demo.Browser;

/// <summary>Sends pipeline events straight to the page's JavaScript.</summary>
public sealed class BrowserEvents(IJSRuntime js) : IDemoEvents
{
    public void Publish(string type, object payload) =>
        ((IJSInProcessRuntime)js).InvokeVoid("sentinelBridge.emit", type, JsonSerializer.Serialize(payload, Json.Options));
}

/// <summary>
/// Invisible root component. Hands the page a reference it uses to call into .NET,
/// standing in for the HTTP API of the server demo.
/// </summary>
public sealed class Bridge : ComponentBase, IDisposable
{
    [Inject] private IJSRuntime Js { get; set; } = default!;
    [Inject] private AgentPipeline Agent { get; set; } = default!;
    [Inject] private FakeStore Store { get; set; } = default!;
    [Inject] private CaseCatalog Cases { get; set; } = default!;
    [Inject] private BrowserEvents Events { get; set; } = default!;
    [Inject] private PolicyText Policy { get; set; } = default!;

    private DotNetObjectReference<Bridge>? _self;

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (!firstRender) return;
        _self = DotNetObjectReference.Create(this);
        await Js.InvokeVoidAsync("sentinelBridge.ready", _self);
    }

    [JSInvokable]
    public string GetCases() => JsonSerializer.Serialize(Cases.Load(), Json.Options);

    [JSInvokable]
    public async Task<string> Run(string requestJson)
    {
        var request = JsonSerializer.Deserialize<RunRequest>(requestJson, Json.Options)
            ?? throw new ArgumentException("Empty request");
        var result = await Agent.RunAsync(request);
        return JsonSerializer.Serialize(result, Json.Options);
    }

    [JSInvokable]
    public void Approve(string id, bool approve) => Agent.ResolveApproval(id, approve);

    [JSInvokable]
    public string GetState() => JsonSerializer.Serialize(Store.Snapshot(), Json.Options);

    [JSInvokable]
    public void Reset()
    {
        Store.Reset();
        Agent.ClearApprovals();
        Events.Publish("state", Store.Snapshot());
    }

    [JSInvokable]
    public string GetPolicy() => Policy.Yaml;

    public void Dispose() => _self?.Dispose();
}
