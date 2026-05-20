# Advanced API Security Scanner

A Burp Suite extension for OWASP API Security Top 10 (2023) testing,
built on the [Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions).

**Compatible with:**
- Burp Suite Professional (with UI tab)
- Burp Suite DAST (headless / automated scanning)

The extension auto-detects the edition at load time; the UI tab is
registered only under Professional.

## Quick start

```bash
mvn clean package -DskipTests
```

Produces `target/burp-api-scanner-2.0.0.jar`. Load via **Extensions →
Installed → Add → Java**.

Requires JDK 17+ (Montoya API requirement) and Maven 3.6+.

The banner in the extension's Output tab will look like:

```
====================================
Advanced API Security Scanner v2.0.0
OWASP API Security Top 10 (2023) coverage
Edition: Burp Suite Professional
AI features: enabled
====================================
```

## Coverage

| OWASP category | Detection |
|---|---|
| API1:2023 — Broken Object Level Authorization | Active + passive |
| API2:2023 — Broken Authentication | Active + passive |
| API3:2023 — Broken Object Property Level Authorization | Active + passive |
| API4:2023 — Unrestricted Resource Consumption | Passive |
| API5:2023 — Broken Function Level Authorization | Active |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | Passive |
| API7:2023 — Server-Side Request Forgery | Active |
| API8:2023 — Security Misconfiguration | Active + passive |
| API9:2023 — Improper Inventory Management | Active + passive |
| API10:2023 — Unsafe Consumption of APIs | Active + Passive |

See [BURP_DAST_GUIDE.md](BURP_DAST_GUIDE.md) for the per-category
detail and the coverage table with notes.

## Distinguishing features

- **HTTP method fuzzing isn't the headline any more** — the original
  v1 implementation flagged every endpoint that responded to an
  unexpected verb, which proved too noisy on real targets. The check
  now focuses on Cross-Site Tracing via TRACE only.
- **Active version probing** — when the path matches `/vN/`, the
  extension actively probes `/v(N-1)/`, `/v(N-2)/`, … on the same
  host and reports each version that returns 2xx. Catches deprecated
  API versions that survive into production.
- **Burp AI integration** (optional) — when `api.ai().isEnabled()` is
  true, two extra features activate automatically:
  - **Passive triage**: false-positive filter on noise-prone passive
    checks (missing-header findings, etc.). Each finding is reviewed
    by the model in context; clear false positives are dropped.
  - **Contextual mass-assignment field discovery**: in addition to
    the hardcoded `isAdmin`/`role`/etc. payloads, the model proposes
    domain-specific privileged fields (`priceOverride`,
    `organizationRole`, …) given the observed JSON body.
  Both features have JVM-property kill switches and time out at 10
  seconds per prompt.

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
│   ├── passive/             # 6 passive checks
│   └── active/              # 7 active checks
├── scanner/EndpointRegistry # shared state for the UI tab
├── ui/ScannerTab            # Swing tab listing discovered endpoints
└── util/IssueBuilder        # fluent AuditIssue construction
```

13 scan checks total, registered individually with the appropriate
`ScanCheckType` (`PER_INSERTION_POINT`, `PER_HOST`, or `PER_REQUEST`).
See [CLAUDE.md](CLAUDE.md) for the full breakdown.

## Contributing

The patterns established during the v2 rewrite are documented in
[CLAUDE.md](CLAUDE.md). When adding a new check, extend
`AbstractPassiveCheck` or `AbstractActiveCheck`, build issues via
`IssueBuilder`, keep constants at the top of the class.

Ideas worth picking up:
- GraphQL-specific testing (introspection, depth, batching)
- Out-of-band detection via Burp Collaborator integration
- Path-traversal probes on URL-like parameters (counterpart to SSRF)

## Disclaimer

For authorized security testing only. Obtain proper authorization
before testing any API or application you don't own.

## License

MIT — see [LICENSE](LICENSE).
