# SentinelAI.NET

**Website:** https://sentinelaidotnet.com (source in [`docs/`](docs/), served by GitHub Pages)

Runtime security for .NET AI apps and agents: scan prompts, retrieved documents and model
output, authorize tool calls, and emit OpenTelemetry evidence.

## Run the demo

Requires the .NET 9 SDK. No API key, no Docker.

```bash
dotnet run --project demo/Demo.AppHost
```

- **Demo UI:** http://localhost:5080. Run a scenario, then flip the Sentinel switch and run it again.
- **Aspire dashboard:** the login link is printed in the console. Open **Traces** to see every
  `sentinel.scan` and `sentinel.tool_guard` span, with blocked decisions marked as errors.

To run without Aspire: `dotnet run --project demo/Demo.Agent` (UI only, no dashboard).

Run the tests, which put every case file through the pipeline:

```bash
dotnet test
```

## Layout

| Path | What it is |
|---|---|
| `src/SentinelAI.Core` | Policy (YAML), scanners, `SentinelEngine`, `ToolGuard`, telemetry |
| `src/SentinelAI.AspNetCore` | `services.AddSentinelAI()` |
| `demo/Demo.Agent` | Support agent, fake data, live UI, `sentinel.yaml`, `cases/` |
| `demo/Demo.AppHost` | Aspire host and dashboard |
| `tests/SentinelAI.Tests` | Scanner, tool-guard and case tests |
| `docs/` | Website (sentinelaidotnet.com) |

## How the demo works

Each run goes through five stages: input scan → retrieval scan → model → tool authorization → output scan.

The model is **simulated** so the demo is deterministic and offline. It models the worst case:
if an attack case's content reaches it, it does exactly what the attacker wanted (the case's
`compromisedEffect`). If Sentinel stops the content first, it behaves normally. So the demo
shows exactly what Sentinel prevents, and its misses are real misses.

The **System state** panel is the ground truth. It records what actually happened to the fake
data (closed accounts, refunds, exports, emails, and URLs a browser would have fetched),
whether Sentinel was on or not. Nothing is ever sent to the network.

## Cases

`demo/Demo.Agent/cases/*.json` is reloaded on every request, so new files show up in the UI
while you present. `00-starter.json` contains:

- **Controls:** normal requests that must pass (false-positive checks).
- **Downstream attacks:** cases that assume the model was already manipulated and test the
  tool firewall and output scanning on their own.

It deliberately contains **no prompt-injection payloads**. Use cases from a published,
third-party source. That is also more convincing to an audience than examples you wrote to
suit your own tool. Some sources to look at:

- Promptfoo red-team plugins: generate cases, then convert the output to this format
- Public prompt-injection benchmarks and datasets, for example on Hugging Face
- The OWASP Top 10 for LLM Applications, for categories and references

Keep payload files you don't want to share out of git by naming them `*.local.json` (ignored).

### Case format

```jsonc
{
  "cases": [
    {
      "id": "unique-id",
      "title": "Shown in the UI",
      "kind": "attack",              // attack | benign
      "category": "indirect",        // control | direct | indirect | multi_turn | tool | output
      "technique": "short label",
      "reference": "where the case comes from",
      "turns": ["user message 1", "user message 2"],     // all turns are scanned together
      "document": { "name": "doc-name", "content": "..." }, // optional: injected into retrieval
      "compromisedEffect": {                              // what a fooled model would do
        "toolCall": { "name": "DeleteAccount", "arguments": { "customerId": "C-2002" } },
        "output": "optional text the model would reply with"
      },
      "expected": "block"            // allow | redact | require_approval | quarantine | block
    }
  ]
}
```

`dotnet test` fails if a protected run doesn't match `expected`, if any protected run causes
damage, or if an attack does no harm with Sentinel off (so the case doesn't prove anything).
A failing case is useful: it's a gap to fix in policy or a reason to add an ML scanner.

## Detection, honestly

The built-in rule scanner is a small set of regex signatures. It normalizes text first
(Unicode folding, invisible-character stripping, tag-character decoding), but it will miss
paraphrased or novel attacks. For real coverage, run an ML classifier behind
`http_scanners` in `sentinel.yaml`. The deterministic controls (the tool firewall, secret and
PII redaction, and exfiltration-URL blocking) hold regardless of how clever the prompt was.
That's the core of the pitch.
