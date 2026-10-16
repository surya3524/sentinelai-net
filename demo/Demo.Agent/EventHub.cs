using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;

namespace Demo.Agent;

/// <summary>Fans out server-sent events to every open browser tab.</summary>
public sealed class EventHub
{
    private readonly ConcurrentDictionary<Guid, Channel<string>> _subscribers = new();

    public (Guid Id, ChannelReader<string> Reader) Subscribe()
    {
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(500) { FullMode = BoundedChannelFullMode.DropOldest });
        var id = Guid.NewGuid();
        _subscribers[id] = channel;
        return (id, channel.Reader);
    }

    public void Unsubscribe(Guid id)
    {
        if (_subscribers.TryRemove(id, out var channel)) channel.Writer.TryComplete();
    }

    public void Publish(string type, object payload)
    {
        var message = $"event: {type}\ndata: {JsonSerializer.Serialize(payload, Json.Options)}\n\n";
        foreach (var channel in _subscribers.Values) channel.Writer.TryWrite(message);
    }
}
