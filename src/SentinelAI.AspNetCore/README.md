# SentinelAI.AspNetCore

SentinelAI for ASP.NET Core apps.

> **Preview.** The API may change before 1.0.

## Take the caller from the signed-in user

Tool authorization needs to know who is acting. This reads it from the user's claims:

```csharp
builder.Services.AddSentinelAI()
    .AddHttpContextCaller(o => o.OwnerIdClaims = ["customer_id"]);
```

The user id comes from `ClaimTypes.NameIdentifier` or `sub`. The owner id, which `ownership_arg` tools compare against, comes from the claims you list, or the user id if you list none. Anonymous requests get no caller, so ownership-checked tools are refused.

Pair it with `SentinelAI.Extensions.AI`:

```csharp
builder.Services.AddChatClient(innerChatClient).UseSentinel().UseFunctionInvocation();
```

## Scan prompts in a minimal API

For endpoints that take a prompt without going through an `IChatClient`:

```csharp
app.MapPost("/ask", (AskRequest req) => ...)
   .ScanWithSentinel<AskRequest>(r => r.Question);   // 400 if policy blocks it
```

More: https://sentinelaidotnet.com · https://github.com/surya3524/sentinelai-net
