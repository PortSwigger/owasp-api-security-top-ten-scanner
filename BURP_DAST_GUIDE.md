# Burp Suite DAST Integration Guide

This document only covers what's specific to running this extension on
**Burp Suite DAST** (headless / automated scanning). For general DAST
configuration — scope, scheduling, scan-speed tuning, OpenAPI import,
CI/CD integration — see the [official DAST documentation](https://portswigger.net/burp/documentation/dast).

The extension also runs unchanged in **Burp Suite Professional**; the
edition is detected at load time and the UI tab is skipped under DAST.

## Loading the extension

The extension is shipped as a single fat JAR. Build with:

```bash
mvn clean package -DskipTests
```

Output: `target/burp-api-scanner-2.0.0.jar`.

In DAST:

1. **Settings → Extensions → Add extension**
2. Upload `burp-api-scanner-2.0.0.jar`
3. Enable the extension

There is no per-DAST configuration — once loaded and enabled, the
extension's checks run as part of any scan that uses Active and/or
Passive audit.

## Verifying the load

The extension banner appears in the extension's output stream. On a
healthy load it reads:

```
====================================
Advanced API Security Scanner v2.0.0
OWASP API Security Top 10 (2023) coverage
Edition: Burp Suite DAST
AI features: enabled       (or "disabled" if Burp AI is off)
====================================
```

The `Edition:` line uses `BurpSuiteEdition.displayName()`, so the value
matches the running product exactly (`Burp Suite DAST`,
`Burp Suite Professional`, or `Burp Suite Community`).

The `AI features:` line reports whether `api.ai().isEnabled()` returned
true. If it says `disabled` when you expect AI to be on, the most
common cause is that Burp AI isn't enabled at the suite level — not an
extension fault.

## OWASP API Top 10 coverage

| Category | Detection | Notes |
|---|---|---|
| **API1:2023** — Broken Object Level Authorization | Active + Passive | ID manipulation, sequential enumeration, unauthenticated access. |
| **API2:2023** — Broken Authentication | Active + Passive | JWT `alg:none`, weak symmetric algs, missing/long `exp`. SQL-injection auth bypass on login endpoints. |
| **API3:2023** — Broken Object Property Level Authorization | Active + Passive | Mass-assignment (hardcoded list + AI-suggested contextual fields when Burp AI is enabled). Sensitive-data exposure in JSON responses. |
| **API4:2023** — Unrestricted Resource Consumption | Passive | Large-response detection, missing rate-limit headers on resource-intensive paths. |
| **API5:2023** — Broken Function Level Authorization | Active | Privilege checks via header stripping / role downgrade. Cross-Site Tracing (TRACE) detection. |
| **API6:2023** — Unrestricted Access to Sensitive Business Flows | Passive | Sensitive-path keyword detection + anti-automation header check. |
| **API7:2023** — Server-Side Request Forgery | Active | URL-like parameter mutation with internal / cloud-IMDS / file:// payloads. |
| **API8:2023** — Security Misconfiguration | Active + Passive | Missing security headers; version-disclosure regex on `Server`, `X-Powered-By` etc.; CORS misconfig; verbose error leakage; SQL / NoSQL / Command / XSS injection. |
| **API9:2023** — Improper Inventory Management | Active + Passive | Path-keyword detection; active probe of older `/v(N-1)/` paths. |
| **API10:2023** — Unsafe Consumption of APIs | Active + Passive | Webhook-endpoint detection (passive); HTTP Parameter Pollution probe across URL and body-form parameters (active). |

All findings use Montoya's four-level severity (`HIGH`, `MEDIUM`, `LOW`,
`INFORMATION`). Legacy `Critical` findings are reported as `HIGH` with
`CERTAIN` confidence — Montoya has no Critical level.

## Burp AI features

Two AI integrations run automatically when `api.ai().isEnabled()` is
true:

- **Passive triage** — each passive finding is sent to the model with
  the request/response context. The model returns `KEEP` or
  `SUPPRESS`. Findings tagged `SUPPRESS` are dropped before they reach
  the Issues tab. Conservative: any failure or ambiguous reply keeps
  the issue.
- **Contextual mass-assignment field discovery** — for JSON request
  bodies, the model proposes domain-specific privileged fields
  (`priceOverride`, `organizationRole`, etc.) in addition to the
  hardcoded list, and the existing test logic injects each one.

Each AI call has a 2-second hard timeout. AI errors are logged but
never fail a scan.

Kill switches (JVM system properties on the DAST process):

- `-Dcom.security.burp.ai.disabled=true` — turn off everything
- `-Dcom.security.burp.ai.triage.disabled=true` — keep field discovery,
  disable triage
- `-Dcom.security.burp.ai.discovery.disabled=true` — keep triage,
  disable field discovery

## Verification checklist

Before running production scans:

- [ ] Extension JAR loaded and enabled in Settings → Extensions
- [ ] Banner shows `v2.0.0`, the correct `Edition:`, and the expected
      `AI features:` state
- [ ] Scan configuration includes Active + Passive audit (passive-only
      will not surface any API5/API7 findings)
- [ ] API endpoints are in scan scope
- [ ] Authentication credentials configured if the API requires them
      (authorization checks need an authenticated baseline to test
      against)

## Troubleshooting

| Symptom | First thing to check |
|---|---|
| Extension fails to load | Errors tab on the extension. JDK 17+ is required (Montoya API requirement). |
| `AI features: disabled` when Burp AI is on | The extension declares `EnhancedCapability.AI_FEATURES`; if `isEnabled()` is still false, confirm the user account has been granted AI access. |
| No findings at all | Confirm Active audit is enabled — most high-severity findings (BOLA, injection, mass assignment, SSRF) require it. |
| Findings missing only on URL-rebuild checks (BOLA, version probe) | Some servers reject duplicate Host headers — this is handled in v2, but worth checking the Errors tab for `4xx` responses on probe requests. |

## Reference

- [Burp Suite DAST documentation](https://portswigger.net/burp/documentation/dast)
- [Extension authoring](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/index.html)
- [CLAUDE.md](CLAUDE.md) — architecture, conventions, gotchas
- [README.md](README.md) — overview and quick-start
