# SentinelAI.Core

The engine behind SentinelAI.NET: a YAML policy, scanners, a tool-call firewall and OpenTelemetry security events. It has no ASP.NET Core or AI-SDK dependency.

> **Preview.** The API may change before 1.0.

Most apps should install an integration instead:

- **`SentinelAI.Extensions.AI`**: `.UseSentinel()` for any `IChatClient`
- **`SentinelAI.AspNetCore`**: the caller from the signed-in user, and an endpoint filter for minimal APIs

## Use directly

```csharp
builder.Services.AddSentinelAI();   // sentinel.yaml, or a built-in default if it's missing

// Scan content yourself
var decision = await engine.ScanAsync(new SecurityScanContext(ContentSource.RetrievedDocument, chunk));
if (decision.Action == SecurityAction.Quarantine) { /* drop the chunk */ }

// Authorize a tool call your own code is about to run
var verdict = toolGuard.Evaluate(call, new ToolCallerContext(userId, ownerId, "my-agent", latestUserMessage));
```

## What's included

- **Scanners:**
  - Prompt-injection rules on normalized text (Unicode folding, invisible-character stripping, tag-character decoding)
  - Secrets
  - PII, with a Luhn check for card numbers
  - Exfiltration URLs
  - An HTTP adapter for external classifiers
- **Policy actions:** `allow`, `redact`, `quarantine`, `require_approval`, `block`, plus an `audit` mode that records decisions without enforcing them.
- **`ToolGuard`:** unknown tools are denied by default, with ownership checks, amount limits, user-intent checks and destination allowlists.
- **OpenTelemetry:** the `SentinelAI` activity source and meter. Add them to your tracer and meter providers.

The built-in default policy is available as `PolicyLoader.DefaultYaml`, a starting point for your own `sentinel.yaml`.

More: https://sentinelaidotnet.com · https://github.com/surya3524/sentinelai-net
