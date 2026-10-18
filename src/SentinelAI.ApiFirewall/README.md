# SentinelAI.ApiFirewall

A request firewall for ASP.NET Core APIs. It inspects what callers send (JSON, YAML, form fields, uploaded files and zip archives) for content that could make your server or its background workers run code or reach places they shouldn't. It runs before your endpoint does.

> **Preview.** The API may change before 1.0.

## Why

Attackers, including AI agents probing APIs at scale, rarely send an obvious exploit. They hide one in data your system processes later: a template expression in a field that should hold a number, a `reference://` or `file://` URL a loader will follow, a YAML tag an unsafe parser will turn into an object, a path that climbs out of its folder. The request looks like normal data; the damage happens later, in a worker.

## Install

```bash
dotnet add package SentinelAI.ApiFirewall --prerelease
```

```csharp
builder.Services.AddSentinelAI();   // reads sentinel.yaml
var app = builder.Build();
app.UseSentinelFirewall();          // early in the pipeline
```

## What it checks

| Check | Catches |
|---|---|
| **Schemas per endpoint** (JSON Schema subset) | Wrong types (a template where an integer belongs), unknown fields, oversized values |
| **Template injection** | Jinja/Twig `{{ }}` `{% %}`, ERB `<% %>`, `${…}` expression languages, JNDI lookups |
| **Unsafe deserialization** | YAML language tags (`!!python/…`), `$type`/`@class` type hints, Java/.NET/pickle serialized objects |
| **Dangerous URLs** | Non-web schemes (`file`, `gopher`, `reference`, `jar`…), URLs to loopback, private, link-local and cloud-metadata addresses (SSRF), including decimal-encoded IPs |
| **Path traversal** | `../` segments, null bytes, absolute system paths, zip entries that escape their folder (zip slip) |
| **Command injection** | Shell chaining and `$( )`. Recorded only by default, since legitimate text trips it more often |
| **Limits** | Body and file size, nesting depth, value count (YAML alias bombs), zip bombs, duplicate JSON keys, content types |

Every value is inspected wherever it sits: query string, body, form field, uploaded file, file inside a zip, including object keys. Values are unwrapped and re-inspected through URL-encoding, base64 and JSON-inside-a-string.

## Policy

```yaml
api_firewall:
  endpoints:
    - path: /datasets/*/config          # * = one segment, ** = any
      methods: [POST]
      content_types: [multipart/form-data]
      uploads:
        allowed_extensions: [.yaml, .json, .zip]
        max_bytes: 1048576
        schema_file: schemas/dataset-config.schema.json
    - path: /search
      schema_file: schemas/search.schema.json
    - path: /templates/**
      allow_detectors: [template_injection]   # this API legitimately accepts templates
  detectors:
    template_injection: quarantine           # block, but keep a copy for review
  urls:
    allowed_hosts: [internal-api.example.com]
```

Blocked requests get a `400` problem response with a trace id and no details, so attackers can't tune payloads against it. Set `expose_details: true` for internal APIs. Quarantined requests are saved to `sentinel-quarantine/`, or to your own `IQuarantineStore`. Use `mode: audit` to record decisions without blocking while you tune the policy. Every decision is an OpenTelemetry event (source `SentinelAI`).

Opt out with `.SkipSentinelFirewall()` on an endpoint or group, or decide per request with `UseSentinelFirewall(o => o.ShouldInspect = ctx => …)`.

## Limits

This reduces risk; it doesn't remove it. Pattern detection catches known techniques, not every new one. Strict schemas are the strongest control here, so define them for every endpoint that accepts structured data. Hostnames aren't resolved, so DNS-rebinding SSRF needs network-level egress controls. Above all, fix the processing code too: never render templates on user data, allowlist URL schemes in loaders, use safe YAML loaders, and process uploads in a sandbox.

More: https://sentinelaidotnet.com · https://github.com/surya3524/sentinelai-net
