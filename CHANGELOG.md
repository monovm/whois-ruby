# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-05

First release.

### Added

- **Four-state availability verdict.** `:available`, `:registered`, `:premium` and
  `:unknown`, plus `:invalid` on `Result` for names that never reached a server.
  `:unknown` is a real answer and is never promoted to `:available`.
- **RDAP support, preferred over WHOIS.** TLD → RDAP endpoint mapping from a bundled
  snapshot of the IANA bootstrap registry (RFC 7484, ~1,200 TLDs). A registered domain
  is read from `objectClassName`, an unregistered one from `errorCode` 404, so no
  pattern matching is involved. Port 43 remains the fallback.
- **Availability detection as an extensible rule chain.** Twelve ordered rules, each an
  object returning a verdict or deferring. `RuleSet` supports `prepend`, `append`,
  `insert_before`, `insert_after`, `replace` and `remove`, so a registry's new wording
  needs one small class rather than a fork.
- **Structured record parsing.** `Parser::Record` exposes registrar, registrant,
  creation/update/expiry dates, nameservers, EPP statuses, DNSSEC and contacts, from
  three parsers (RDAP JSON, ICANN RDD, generic key/value) selected per response. Raw
  fields stay reachable. GDPR redaction placeholders are reported as `nil`.
- **Registrar referral following.** Thin registries are chased one hop to the
  registrar's server for the fuller record. The referral enriches the record only; the
  registry keeps authority over the verdict.
- **Concurrent bulk checks** with per-host throttling, so a large single-TLD batch does
  not trigger a registry rate limit.
- **Transport middleware**: in-process response cache, per-host throttle, retry for
  transient failures only, and an instrumentation hook.
- **Punycode / IDN support** via an RFC 3492 implementation with no dependencies,
  verified against the RFC test vectors and the published IDN ccTLD ACE forms.
- **`explain`** on the client, the module and the handler, returning the deciding rule,
  its evidence and the full trace of every rule consulted.
- **CLI** `monovm-whois`, with `--json`, `--details`, `--raw`, `--prefer`, `--timeout`,
  `--concurrency`, `--tlds`, `--[no-]cache`, `--[no-]colour` and `--tld-count`. Exits
  non-zero when any name came back inconclusive.
- **`WhoisHandler`**, a single-domain handler object, with camelCase method aliases
  (`isAvailable`, `getWhoisMessage`, …) for code migrating from camelCase WHOIS APIs.
- **Definition overrides** through `MONOVM_WHOIS_DEFINITIONS`, so a stale registry
  entry can be corrected without a gem release.
- Error taxonomy under `MonoVM::Whois::Error`: `InvalidDomainError`,
  `UnsupportedTldError`, `DefinitionsError`, `ConnectionError`, `TimeoutError`,
  `ServerRefusedError`, `EmptyResponseError`.

### Fail-safe design decisions

Every choice points the same way — declining to guess where a permissive heuristic
would answer "available". See the table in the README for the full list. The main ones:

- Rate limits, blocked clients, retired port 43 endpoints, HTTP 4xx/5xx and empty
  responses are `:unknown`, not `:available`.
- Reaching an address registry (RIPE, ARIN, APNIC) by a misconfigured TLD mapping is
  `:unknown`, not `:available` for every name in that TLD.
- "Fewer than two registration fields" is no longer treated as availability. That
  inference converts any non-answer into a free domain. It survives only as the
  `recordless` rule, opt-in per TLD via `available_when_empty`.
- DENIC's `Status: invalid` is `:registered`, not `:available`.
- Premium and reserved names are `:premium`, not `:available`.
- Field matching tolerates dot-padded keys (`status.........: Registered`), which
  several registries emit and a plain `status:` match misses.
- TLS certificates are verified by default.

### Notes

- Requires Ruby 3.1 or newer. No runtime dependencies.
- The bundled RDAP bootstrap snapshot was taken 2026-07-23 and can be refreshed with
  `rake data:refresh_rdap`.

[1.0.0]: https://github.com/monovm/whois-ruby/releases/tag/v1.0.0
