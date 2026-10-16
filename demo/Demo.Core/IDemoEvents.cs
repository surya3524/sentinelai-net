namespace Demo.Agent;

/// <summary>
/// Where the pipeline sends live updates: server-sent events in the server demo,
/// direct JavaScript calls in the WebAssembly demo.
/// </summary>
public interface IDemoEvents
{
    void Publish(string type, object payload);
}
