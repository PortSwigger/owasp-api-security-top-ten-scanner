# Advanced API Security Scanner

A Burp Suite extension for OWASP API Security Top 10 (2023) testing,
built on the [Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions).

**Compatible with:**
- Burp Suite Professional (with UI tab)
- Burp Suite DAST (headless / automated scanning)

The extension auto-detects the edition at load time; the UI tab is
registered only under Professional.

> **Scope (read this first).** This extension deliberately covers **only
> the API-specific categories Burp's native scanner does not already
> test**. Checks that duplicated native coverage — injection, SSRF, HTTP
> method abuse, JWT/authentication, CORS/CSP/security-misconfiguration —
> were removed in v2.2.0, because the native scanner reports them at
> higher confidence and duplicate findings are the single most common
> reason a BApp submission is rejected. Run this **alongside** Burp's
> built-in scanner, not instead of it. The
> [OWASP → native mapping](#owasp-coverage-and-native-cross-reference)
> below tells you which native checks cover the rest.
>
> The complete, self-contained build that *does* re-detect those classes
> (15 checks) is preserved on the **`full` branch** and the **`v2.1.2`
> tag** for users who want a one-extension sweep and accept the overlap.

## Quick start

```bash
mvn clean package -DskipTests
```

Produces `target/burp-api-scanner-2.2.0.jar`. Load via **Extensions →
Installed → Add → Java**.

Requires JDK 17+ (Montoya API requirement) and Maven 3.6+.

The banner in the extension's Output tab will look like:

```
====================================
Advanced API Security Scanner v2.2.0
OWASP API Security Top 10 (2023) coverage
Edition: Burp Suite Professional
AI features: enabled
====================================
```

## What this extension checks (the lean build)

Nine checks, each targeting an API-specific weakness Burp's native
scanner does not cover:

| OWASP category | Check(s) | Type |
|---|---|---|
| API1:2023 — Broken Object Level Authorization | ID manipulation + sequential enumeration (content-compared, not just 2xx) | Active |
| API3:2023 — Broken Object Property Level Authorization | Mass assignment (single-field, combo, AI-suggested fields); excessive data exposure (unbounded arrays, over-broad projections) | Active + passive |
| API4:2023 — Unrestricted Resource Consumption | Large responses; missing rate-limit headers on heavy paths | Passive |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | Business-flow endpoint heuristics | Passive |
| API9:2023 — Improper Inventory Management | Active version probing; deprecated / debug / version-disclosure paths | Active + passive |
| API10:2023 — Unsafe Consumption of APIs | HTTP parameter pollution; webhook-receiver pointers | Active + passive |

## OWASP coverage and native cross-reference

The categories below are **intentionally delegated to Burp's native
scanner**. Enable the built-in scanner and cross-check these issues —
the extension does not re-detect them.

| OWASP category | Use these native Burp Scanner checks instead |
|---|---|
| API2:2023 — Broken Authentication | JWT signature not verified · JWT *none* algorithm supported · JWT self-signed JWK header supported · JWT weak/guessable secret · JSON Web Key Set disclosed · Unencrypted communications |
| API5:2023 — Broken Function Level Authorization | Broken access control |
| API7:2023 — Server-Side Request Forgery | Out-of-band resource load (HTTP) · External service interaction · File path traversal |
| API8:2023 — Security Misconfiguration | CORS: arbitrary origin trusted · Content security policy issues · Strict transport security not enforced · Frameable response (clickjacking) · Unencrypted communications · Source code disclosure |

Two categories the extension keeps also **partially** overlap native, so
their issues carry a "Related Burp Scanner checks" line pointing you to
the native counterpart:

- **API1 BOLA** — the unauthenticated-access angle is Burp's *Broken
  access control*. The extension keeps the ownership/enumeration angle
  (different object returned for a manipulated ID).
- **API3 data exposure** — specific value leaks are Burp's *Password
  returned in later response*, *Credit card numbers disclosed*, *Private
  key disclosed*, etc. The extension keeps the response-*shape* signal
  (unbounded arrays, excessive field counts) those don't report.

## Distinguishing features

- **Active version probing** — when the path matches `/vN/`, the
  extension actively probes `/v(N-1)/`, `/v(N-2)/`, … on the same host
  and reports each version that returns 2xx. Catches deprecated API
  versions that survive into production.
- **Content-compared BOLA** — the object-level-authorization check fires
  only when a manipulated identifier returns a *materially different
  object* than the baseline, not merely a 2xx. That is what justifies
  Firm confidence on a single observation.
- **Burp AI integration** (optional) — when `api.ai().isEnabled()` is
  true, two extra features activate automatically:
  - **Passive triage**: false-positive filter on noise-prone passive
    checks. Each finding is reviewed by the model in context; clear
    false positives are dropped. Attacker-controlled HTTP content is
    wrapped in structural delimiters and treated as data, and the model's
    reply is parsed with safe-failure semantics (ambiguous → keep the
    finding).
  - **Contextual mass-assignment field discovery**: in addition to the
    hardcoded `isAdmin`/`role`/etc. payloads, the model proposes
    domain-specific privileged fields (`priceOverride`,
    `organizationRole`, …) given the observed JSON body.
  Both features have JVM-property kill switches and time out at 2
  seconds per prompt on a bounded daemon thread pool.

## Documentation

- [CLAUDE.md](CLAUDE.md) — architecture, conventions, gotchas. Read
  this before contributing.
- [BURP_DAST_GUIDE.md](BURP_DAST_GUIDE.md) — DAST-specific load,
  banner, coverage, troubleshooting.
- [VALIDATION_GUIDE.md](VALIDATION_GUIDE.md) — how to validate
  findings by confidence level.

## Architecture (high level)

```
com.security.burp/
├── BurpExtender.java        # entry; declares AI capability, registers everything
├── ai/                      # AI client + triage + field discovery
├── checks/
│   ├── AbstractPassiveCheck #   base classes — exception handling, triage
│   ├── AbstractActiveCheck
│   ├── passive/             # 5 passive checks
│   └── active/              # 4 active checks
├── scanner/EndpointRegistry # shared state for the UI tab
├── ui/ScannerTab            # Swing tab listing discovered endpoints
└── util/IssueBuilder        # fluent AuditIssue construction
```

9 scan checks total, registered individually with the appropriate
`ScanCheckType` (`PER_INSERTION_POINT`, `PER_HOST`, or `PER_REQUEST`).
See [CLAUDE.md](CLAUDE.md) for the full breakdown and the `main` vs
`full` branch split.

## Contributing

The patterns established during the v2 rewrite are documented in
[CLAUDE.md](CLAUDE.md). When adding a new check, extend
`AbstractPassiveCheck` or `AbstractActiveCheck`, build issues via
`IssueBuilder`, keep constants at the top of the class. **New checks on
`main` must not duplicate native scanner coverage** — that is the
property the lean build exists to preserve.

Ideas worth picking up:
- GraphQL-specific testing (introspection, depth, batching) — genuinely
  not covered by the native scanner
- Out-of-band detection via Burp Collaborator integration

## Disclaimer

For authorized security testing only. Obtain proper authorization
before testing any API or application you don't own.

## License

MIT — see [LICENSE](LICENSE).
