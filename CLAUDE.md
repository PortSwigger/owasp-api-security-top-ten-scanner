# CLAUDE.md

Guidance for Claude (and any human reviewer) working in this repository.

This is a Burp Suite extension implementing OWASP API Security Top 10
(2023) coverage. It is built on the Montoya API and targets Burp Suite
Professional and Burp Suite DAST.

## Architecture

```
src/main/java/com/security/burp/
├── BurpExtender.java              # Entry point. Declares EnhancedCapability.AI_FEATURES,
│                                  # registers checks, wires the unloading handler.
├── ai/                            # AI integration layer (optional, gates on api.ai().isEnabled())
│   ├── AiClient.java              #   wrapper around api.ai() with executor + 2s timeout + cache
│   ├── AiTriage.java              #   passive-finding KEEP/SUPPRESS filter
│   └── AiFieldDiscovery.java      #   contextual privileged-field suggestions for mass assignment
├── checks/
│   ├── AbstractPassiveCheck.java  # Base class. Centralises endpoint recording, exception
│   │                              # handling (with stack-trace logging), AI triage.
│   ├── AbstractActiveCheck.java   # Same, for active checks.
│   ├── passive/                   # 6 passive checks, all extend AbstractPassiveCheck
│   └── active/                    # 9 active checks, all extend AbstractActiveCheck
│       └── injection/             # InjectionCheck splits into 3 files (coordinator,
│                                  # AuthBypassTester, InjectionPayloads)
├── scanner/
│   └── EndpointRegistry.java      # Bounded thread-safe state shared with the UI tab.
│                                  # Cleared on unload.
├── ui/
│   └── ScannerTab.java            # Swing JPanel + JTable backed by EndpointRegistry.
│                                  # dispose() stops the refresh timer.
└── util/
    ├── HttpUtils.java             # content-type / API-path / modifying-method helpers
    └── IssueBuilder.java          # fluent AuditIssue construction (replaces legacy
                                   # CustomScanIssue). Maps "Critical" -> Montoya HIGH.
```

## Build commands

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk        # or any JDK 17+
export PATH="$JAVA_HOME/bin:$PATH"
mvn clean package -DskipTests
```

Output: `target/burp-api-scanner-2.1.0.jar` (~370 KB fat JAR).

Load in Burp via **Extensions → Installed → Add → Java**.

## Conventions

These are the patterns established across all 15 checks. Stick to them
when adding new ones — Hannah's review feedback was the catalyst for the
v2 rewrite, and breaking these breaks the property she cared about
(reviewable code).

- **Each check extends `AbstractPassiveCheck` or `AbstractActiveCheck`.**
  Subclasses implement one method (`audit(...)`) and don't worry about
  exception handling, endpoint recording, or AI triage.
- **Constants at the top of the class.** Path keywords, payload tables,
  HTML strings for issue descriptions — pull them up.
- **Methods under ~50 LOC**, classes under ~250 LOC. The largest current
  file is `SecurityMisconfigCheck.java` at 305 LOC because it has 5 sub-
  checks; further splitting would just add ceremony.
- **No swallowed exceptions.** The base classes log uncaught throwables
  with a full stack trace via `api.logging().logToError(...)`. If you
  catch yourself, log the same way.
- **Issues built via `IssueBuilder`.** Don't call `AuditIssue.auditIssue(...)`
  directly — the builder centralises the legacy "Critical" → Montoya
  HIGH mapping (Montoya has no Critical level).
- **Detection logic is the source of truth.** AI is a *filter* (triage
  drops false positives) or an *augmentation* (field discovery adds
  contextual payloads). It never invents findings on its own.

## Gotchas (real things that bit us)

1. **`EnhancedCapability.AI_FEATURES` must be declared.** Without this
   override on `BurpExtension`, `api.ai().isEnabled()` returns false even
   when Burp AI is on at the suite level. The banner will say
   "AI features: disabled" and you will lose an afternoon trying to
   figure out why. See `BurpExtender.enhancedCapabilities()`.

2. **`HttpRequest.httpRequestFromUrl(...)` already sets a Host header.**
   Adding `withAddedHeaders(rr.request().headers())` on top duplicates
   it, and many servers reject duplicate Host with a 4xx — silently
   masking real findings (BOLA, version-probe). Re-attach all original
   headers EXCEPT Host. See `BrokenObjectAuthCheck.sendWithReplacedId`
   and `DeprecatedVersionProbeCheck.rebuildAtVersion` for the right shape.

3. **AI calls must time out.** `api.ai().prompt().execute(...)` is
   synchronous and can block indefinitely. `AiClient` runs prompts on a
   dedicated daemon executor with a 2s hard timeout, so one stuck
   prompt cannot block a scan thread. PortSwigger BApp criterion #5.

4. **Use `edition.displayName()`, not the raw enum.** The Montoya enum
   constant is `BurpSuiteEdition.ENTERPRISE_EDITION` for backward
   compatibility, but customers know the product as "Burp Suite DAST".
   `displayName()` returns the current product name.

5. **UI tabs need `applyThemeToComponent()`.** Without it, the tab uses
   Swing defaults — looks wrong against a dark Burp. Call it on the
   component before `registerSuiteTab`.

6. **The unloading handler must release everything.** Executors, timers,
   registries, UI references. PortSwigger BApp criterion #6. See
   `BurpExtender.registerUnloadingHandler` for the canonical shape.

7. **JSON-format AI prompts are more reliable than free-text.** The AI
   integration uses structured prompts that ask for JSON (e.g.
   `{"verdict": "KEEP" | "SUPPRESS"}`) and parses with Gson. Free-text
   parsing produces flaky results on the long tail of model outputs.

8. **Don't bulk-rewrite via a sub-agent without reviewing the output.**
   The first Montoya migration (closed PR #2) compiled cleanly but
   produced unreviewable code (one 666-LOC check, swallowed exceptions,
   dense logic). The v2 rewrite was hand-written file by file with
   the patterns above. "Compile-clean" ≠ "good code".

## Adding a new check

1. Decide passive (no outbound traffic) or active (sends payloads).
2. Create the class under `checks/passive/` or `checks/active/` and
   extend the corresponding `Abstract*Check` base class.
3. Add constants at the top, helpers private, single `audit(...)` body.
4. Build issues via `IssueBuilder.issue(rr).name(...).detail(...).build()`.
5. Register in `BurpExtender.registerScanChecks(...)` with the right
   `ScanCheckType`:
   - `PER_INSERTION_POINT` for parameter-mutating checks
   - `PER_HOST` for endpoint/method-level checks
   - `PER_REQUEST` for passive checks
6. Run `mvn clean package` — the build will fail loudly on style /
   import / typing problems before the JAR is produced.

## Reference

- [Montoya API Javadoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Montoya API examples](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [BApp Store acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/bapp-store-acceptance-criteria)
- [Extension template project](https://github.com/PortSwigger/extension-template-project) — the upstream
  CLAUDE.md and `docs/*` define PortSwigger's official conventions.
- See [BURP_DAST_GUIDE.md](BURP_DAST_GUIDE.md) for headless / DAST
  loading guidance.
