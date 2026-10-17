# SentinelAI.Extensions.AI

Runtime security for any `IChatClient` (Azure OpenAI, OpenAI, Ollama, the Microsoft Agent Framework and anything else built on Microsoft.Extensions.AI).

> **Preview.** The API may change before 1.0.

## Install

```bash
dotnet add package SentinelAI.Extensions.AI --prerelease
```

## Use

```csharp
builder.Services.AddSentinelAI();                 // loads sentinel.yaml from the content root

builder.Services.AddChatClient(innerChatClient)
    .UseSentinel()                                // before UseFunctionInvocation()
    .UseFunctionInvocation();
```

Then tell SentinelAI who is calling, so tool calls can be authorized:

```csharp
var options = new ChatOptions { Tools = [lookupOrder, issueRefund] }
    .WithSentinelCaller(new SentinelCaller(UserId: user.Id, OwnerId: user.CustomerId));

var response = await chatClient.GetResponseAsync(messages, options);
```

In ASP.NET Core you can take the caller from the signed-in user instead. See `SentinelAI.AspNetCore`.

## What it does

| Stage | What happens |
|---|---|
| User input | Scanned before the model is called. If it's blocked, the model never sees it. |
| Tool calls | Every `AIFunction` is wrapped. Each call is checked against the policy as it runs: unknown tools are denied, and there are ownership checks, amount limits, user-intent checks, destination allowlists and human approval. |
| Tool results | Scanned for instructions aimed at the assistant before the model reads them. |
| Model output | Secrets and personal data are redacted. Replies that would leak data through image URLs are withheld. |
| Telemetry | Every decision is an OpenTelemetry event on the request's trace (source `SentinelAI`). |

Streaming responses are buffered so the full reply can be checked before any of it is shown.

`response.AdditionalProperties["sentinel.action"]` holds the strongest action taken.

## Policy

Put `sentinel.yaml` in your app (copy it to the output folder). List every tool the agent may call, since tools that aren't listed are blocked:

```yaml
tools:
  LookupOrder: { action: allow, ownership_arg: customerId }
  IssueRefund:
    action: allow
    ownership_arg: customerId
    require_user_intent: [refund]
    amount_arg: amount
    approval_above: 150
    max_amount: 500
  DeleteAccount: { action: require_approval, ownership_arg: customerId }
```

Calls that need approval go to your `IToolApprovalHandler`: `services.AddSentinelAI().AddApprovalHandler<MyHandler>()`. Without a handler, they aren't executed.

## Limits

The built-in prompt-injection rules are regex signatures. They catch obvious attacks, not reworded ones. For real coverage, add an ML classifier under `http_scanners` in the policy. The tool firewall, redaction and exfiltration blocking are deterministic and don't depend on detecting the attack.

More: https://sentinelaidotnet.com · https://github.com/surya3524/sentinelai-net
