# Validation Guide

How to validate findings reported by this extension. Organised by
Montoya's confidence levels (`CERTAIN` / `FIRM` / `TENTATIVE`) — the
higher the confidence, the less manual validation is required.

> **Scope.** This guide covers the **lean BApp build** (`main`, 9
> checks). Findings for injection, SSRF, JWT/authentication, CORS/CSP and
> other security-misconfiguration classes come from **Burp's native
> scanner**, not this extension — validate those per Burp's own issue
> documentation. See the
> [OWASP → native mapping](BURP_DAST_GUIDE.md#owasp-api-top-10-coverage).

## Severity mapping note

The extension uses Montoya's four-level severity (`HIGH`, `MEDIUM`,
`LOW`, `INFORMATION`). Legacy "Critical" findings are reported as
`HIGH` with `CERTAIN` confidence — Montoya has no Critical level. The
combination of `HIGH` + `CERTAIN` is the practical equivalent.

## AI triage note

When Burp AI is enabled, the [passive triage layer](BURP_DAST_GUIDE.md#burp-ai-features)
has already filtered findings the model considered clear false
positives in context. Anything that reaches the Issues tab is at least
a "the model thinks this is worth looking at" finding — but it can
still benefit from manual validation per the guidance below. Triage is
conservative (KEEP-when-in-doubt), not authoritative.

---

## CERTAIN — proven by the request/response itself

| Finding | Why it's CERTAIN |
|---|---|
| **API version disclosed in header** | The header value is itself the disclosure — no inference involved. |

The extension keeps only one self-proving finding. The injection,
command-execution, SSRF and TRACE findings that used to live here now
come from Burp's native scanner (validate them per Burp's issue
documentation). For these: confirm scope ownership, then prioritise.

---

## FIRM — strong evidence, context-dependent

These findings have substantive evidence, but the *meaning* of that
evidence depends on context. Walk through the checklist before
reporting.

### API1:2023 — BOLA / ID manipulation

**Finding:** changing an object ID in the URL returned a *different
object* than the original request (the response body differs from the
baseline — a 2xx alone does not fire this check).

**Questions to answer:**
1. Is the authenticated user *supposed* to see that other ID?
2. Are these public profiles (Twitter / LinkedIn shape)?
3. Is the user an admin / same-org member with legitimate access?

**How to validate:**
- Compare with the application's documented role model.
- Re-test as a different (non-admin) user.
- Confirm the returned data is genuinely cross-tenant or cross-user.

**True positive indicators:** private user data accessible across
tenants; PII accessible without explicit access grant.
**False positive scenarios:** public profile endpoints; legitimate
admin access; shared / collaborative resources.

> **Cross-reference.** The *unauthenticated*-access angle (no session at
> all) is Burp's native **Broken access control** issue — this check
> deliberately does not re-detect it. Cross-check that issue for the
> same host.

### API1:2023 — Sequential ID enumeration

**Finding:** multiple adjacent numeric IDs each return a *distinct
object* (different response bodies), suggesting an enumerable namespace.

**Questions to answer:** Is the namespace meant to be enumerable
(public articles, public products)? Or is this leaking the existence
of private records?

**How to validate:** check whether the returned objects contain any
sensitive data, or whether the act of enumeration itself violates a
property (e.g. unlisted resources).

### API3:2023 — Mass assignment

**Finding:** the extension injected `isAdmin: true` (or an AI-suggested
contextual field like `priceOverride`) and the field was accepted and
echoed in the response — and was *not* already present in the baseline.

**Questions to answer:**
1. Was the field actually saved server-side, or just echoed?
2. Does the field grant real privileges, or is it cosmetic?

**How to validate:**
- Re-fetch the modified record without the injection. Does the field
  persist?
- Attempt a privileged operation that should now succeed if the field
  was honoured (e.g. an admin-only endpoint).
- For AI-suggested fields (`priceOverride`, etc.), perform the
  business action and verify the price / state actually changed.

**False positive scenarios:** API echoes input but doesn't persist it;
field is validated and silently ignored. (This is exactly why the check
reports **Firm**, not Certain — an echoed value isn't proof of
persistence.)
**True positive indicators:** field persists across requests; the
user can now perform actions they previously couldn't.

### API3:2023 — Excessive data exposure (response shape)

**Finding:** the response is an **unbounded array** (100+ items with no
pagination signal) or its items carry an **excessive number of distinct
fields** (over-broad projection). Note: the extension no longer flags
fields by sensitive-sounding *name* — that overlaps native checks.

**Questions to answer:**
1. Is the large/wide response intended (a legitimate bulk export)?
2. Does the client actually consume every field, or is the back-end
   model being serialised wholesale?

**How to validate:**
- Check for a pagination mechanism the check might have missed
  (cursor in body, non-standard header).
- Inspect the field set for back-end-only properties leaking through.

> **Cross-reference.** *Specific value* leaks (passwords, card numbers,
> private keys in the body) are Burp's native **"Password returned in
> later response"**, **"Credit card numbers disclosed"**, etc. This
> check covers the response *shape* those don't.

### API9:2023 — Deprecated version reachable

**Finding:** the current path was `/v3/...` and an older `/v(N-1)/...`
returned 2xx on the same host. (Note: `/v1/` is no longer treated as
deprecated on its own — it is the current version on most APIs.)

**Questions to answer:**
1. Is the old version officially supported (long deprecation window)?
2. Or is it actually meant to be off?

**How to validate:**
- Diff the responses — does the old version expose endpoints or
  fields that the new version intentionally removed?
- Check whether the old version misses security fixes documented for
  the new version.

---

## TENTATIVE / INFORMATION — heuristic, high false-positive rate

These findings come from heuristics with no direct exploit proof.
They're worth knowing about but should never be reported as confirmed
without manual validation.

### API4:2023 — Missing rate limiting (Information)

**Finding:** no `X-RateLimit-*` / `RateLimit-*` headers on a
resource-intensive endpoint path (search, export, report, …).

**How to validate:**
- Send a burst of requests (e.g. 200 in 30 seconds).
- Watch for 429 / 503 / 502 responses, increased latency, or IP
  blocks.
- Confirm with the WAF / CDN config if accessible — rate limiting may
  exist at a layer that doesn't surface response headers.

**False positive scenarios:** WAF / Cloudflare handles rate limiting
without surfacing headers; legitimate low-value endpoint that doesn't
need limiting. (Reported Information/Tentative for exactly this reason.)

### API6:2023 — Missing anti-automation on sensitive flow

**Finding:** a sensitive-keyword path (`/checkout`, `/transfer`,
`/withdraw`, …) lacks anti-automation indicators (CAPTCHA tokens,
rate-limit headers).

**How to validate:**
- Attempt to drive the endpoint at scale (10–100x normal use).
- Confirm whether the underlying business action repeats unimpeded.
- Consider whether the action has business impact at scale (financial
  loss, account creation flood, ticket scalping).

### API9:2023 — Debug / management endpoint exposed

**Finding:** path looks like `/debug`, `/actuator`, `/metrics`,
`/internal`, etc. (Documentation paths like `/swagger` and `/openapi`
are no longer flagged — they are intentional published artefacts and
Burp's native scanner reports exposed API definitions.)

**How to validate:**
- Is the endpoint intentionally public (e.g. a public health probe)?
- Does it leak runtime configuration or grant administrative
  actions?
- Is access restricted by network controls (mTLS, allow-list)?

### API10:2023 — HTTP Parameter Pollution

**Finding:** sending the same parameter twice (once with the original
value, once with a marker) produced a response that **differs** from the
single-parameter baseline — any status change, in either direction, or a
material body-length change beyond the endpoint's natural jitter.

**How to validate:**
- Reproduce the request in Repeater with the polluted parameter.
- Try several pollution-value variants: empty string, a value the
  application is likely to treat specially (`admin`, `1`, `0`,
  `true`), and the marker the scanner used. Different frameworks
  pick different values from the duplicate set — knowing *which* the
  server picks is part of the exploit.
- If the parameter participates in authorisation (e.g.
  `?user_id=123&user_id=456` returns user 456's data), this is a
  direct access-control bypass.
- If the parameter participates in filtering (e.g. WAF reads first
  value, app reads last), the inconsistency is exploitable across
  the security boundary.

> **On a `200 → 400` result:** do **not** dismiss it as the framework
> safely rejecting a duplicate. If polluting with the marker flips a 200
> to a 400, the server is reading the *last* value (the marker) and
> discarding the legitimate first one — that is the override primitive
> HPP exploits. A reviewer confirmed one such case as a genuine
> auth-relevant HPP, so the check fires on it (Tentative).

**False positive scenarios:** the response varies for unrelated reasons
(timestamps, caching) — the jitter guard suppresses most of these, but
verify in Repeater.
**True positive indicators:** the polluted response reveals different
data than the baseline; the security control (WAF, framework router)
treats the parameter set differently than the application code.

### API10:2023 — Webhook receiver (Information)

**Finding:** path matches a webhook pattern (`/webhook`,
`/inbound-webhook`, …). This is a **pointer for manual review**, not a
confirmed flaw — the check has no evidence the handler is actually
unsafe.

**How to validate:**
- Send a synthetic payload from an unrelated source. Does the
  endpoint accept it?
- If the upstream provider documents a signing scheme (HMAC, etc.),
  check whether the application implements verification.

---

## Reporting tips

- **Treat `CERTAIN + HIGH` as the equivalent of legacy `Critical`** —
  these findings should be the headline of any report.
- **Always include the request/response evidence** that fired the
  finding — Burp captures it automatically; make sure it's exported
  with the report.
- **For AI-augmented findings** (mass assignment via field discovery,
  triage-survived findings), note in the report which payloads /
  fields the AI proposed. The reviewer should see the model's
  contribution so they can sanity-check it.
- **For TENTATIVE / INFORMATION findings** — never report without manual
  validation. False positives erode trust in the whole report.
- **Run Burp's native scanner alongside this extension** — the
  categories this build delegates (API2/API5/API7/API8) only surface if
  the built-in scanner is enabled.
