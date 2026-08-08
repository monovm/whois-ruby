# monovm-whois-ruby

Domain WHOIS and RDAP lookups for Ruby, with availability detection that says
"I don't know" instead of guessing.

No runtime dependencies.

```ruby
require "monovm-whois-ruby"

MonoVM::Whois.available?("monovm.com")   # => false
MonoVM::Whois.lookup("monovm.com").record.expires_on
MonoVM::Whois.whois(%w[monovm google.com])
```

## Installation

```ruby
gem "monovm-whois-ruby"
```

or

```sh
gem install monovm-whois-ruby
```

Requires Ruby 3.1 or newer.

## Why the availability status has four values

Most WHOIS libraries answer "is this domain available?" with a boolean. That collapses two very different situations —
*this domain is registered* and *I could not find out* — into the same `false`.

The expensive failure is the other direction. A WHOIS server that is rate-limiting
you, or that has retired port 43, or that answered with an HTML error page, sends back
text containing none of the words that mean "registered". A detector built from
heuristics falls through all of them and lands on its most permissive rule, which
reports the domain as free. For a registrar that means putting a registered domain in
a customer's shopping cart.

So a lookup here returns one of five statuses, and `available` means it was positively
established:

| Status | Meaning |
|---|---|
| `:available` | The registry said this name is not registered. |
| `:registered` | The name exists. |
| `:premium` | Unregistered, but reserved or premium-priced — not obtainable normally. |
| `:unknown` | No verdict. Rate limited, unreachable, unreadable. **Ask again later.** |
| `:invalid` | The input was not a usable domain, or its TLD has no known server. |

```ruby
result = MonoVM::Whois.lookup("example.com")

result.status        # => :registered
result.available?    # => false
result.registered?   # => true
result.unknown?      # => false
result.conclusive?   # => true
```

`available?` is safe to branch on. Treating `!available?` as "registered" is not —
that is what `registered?` is for.

## Usage

### One domain

```ruby
result = MonoVM::Whois.lookup("monovm.com")

result.name              # => "monovm.com"
result.tld               # => ".com"
result.sld               # => "monovm"
result.status            # => :registered
result.whois_message     # the raw registry response, verbatim
result.record.registrar  # => "Example Registrar, LLC"
```

### Many domains, and names without a TLD

```ruby
MonoVM::Whois.whois("monovm.com")
# => {"monovm.com" => :registered}

MonoVM::Whois.whois(%w[monovm google.com])
# => {"monovm.com"  => :registered,
#     "monovm.net"  => :registered,
#     "monovm.org"  => :available,
#     "monovm.info" => :available,
#     "google.com"  => :registered}

MonoVM::Whois.whois("monovm", popular_tlds: %w[.io .dev])
# => {"monovm.io" => :registered, "monovm.dev" => :available}
```

Bulk checks run concurrently (8 threads by default) and are throttled per host, so a
list of 500 `.com` names does not get your IP rate-limited by Verisign.

Duplicates, mixed case, URLs and trailing dots all collapse to one lookup:
`"EXAMPLE.COM"`, `"https://example.com/path"` and `"example.com."` are the same name.

### The parsed record

```ruby
record = MonoVM::Whois.lookup("example.com").record

record.registrar             # => "Example Registrar, LLC"
record.created_on            # => 1995-08-14 04:00:00 UTC
record.expires_on            # => 2027-08-13 04:00:00 UTC
record.days_until_expiry     # => 372
record.nameservers           # => ["ns1.example.com", "ns2.example.com"]
record.statuses              # => ["clientTransferProhibited"]
record.registrant            # => nil when the registry redacts it
record.dnssec?               # => false
record.transfer_prohibited?  # => true
record.expiring?             # => false
record.contacts[:admin]      # => {name: ..., email: ...}
record["Registry Domain ID"] # any raw field, by its original key
```

Post-GDPR placeholders (`REDACTED FOR PRIVACY`, `Data Protected`, …) are reported as
`nil` rather than as a registrant literally named "REDACTED FOR PRIVACY".

### Why a verdict came out that way

```ruby
MonoVM::Whois.explain("example.com")
# => {domain: "example.com",
#     status: :registered,
#     reason: "RDAP returned a domain object",
#     trace: [{rule: "server_refusal", matched: false},
#             {rule: "wrong_registry",  matched: false},
#             {rule: "rdap_object",     matched: true, status: :registered,
#              evidence: "example.com"}],
#     endpoint: "https://rdap.verisign.com/com/v1/domain/"}
```

Every rule that was consulted is in the trace, in order, with the one that decided and
the text it matched. This is the first thing to reach for when a classification looks
wrong.

### Single-domain handler

`WhoisHandler` wraps one lookup in an object, with camelCase aliases for code
being migrated from camelCase WHOIS APIs:

```ruby
handler = MonoVM::Whois::WhoisHandler.whois("monovm.com")

handler.available?           # also handler.isAvailable
handler.valid?               # also handler.isValid
handler.whois_message        # also handler.getWhoisMessage
handler.tld                  # also handler.getTld
handler.availability_details # also handler.getAvailabilityDetails
```

The four-state verdict described above applies here too: `handler.unknown?` is a
real answer, distinct from both `available?` and `registered?`.

### Command line

```sh
$ monovm-whois monovm.com google.com
monovm.com  registered
google.com  registered

$ monovm-whois monovm --tlds .io,.dev --details
$ monovm-whois example.com --json
$ monovm-whois example.com --prefer whois --timeout 5
$ monovm-whois --tld-count
2043 TLDs supported
```

Exit code is 0 when every name got a real answer and 1 when any came back `unknown` or
`invalid` — so a script can tell "definitely free" from "could not find out".

### Configuration

```ruby
MonoVM::Whois.configure do |config|
  config.prefer = :whois             # port 43 before RDAP (default: :rdap)
  config.follow_referrals = true     # chase thin registries to the registrar
  config.concurrency = 8             # threads for bulk checks
  config.throttle_interval = 0.5     # minimum seconds between queries to one host
  config.cache_ttl = 300             # in-process response cache
  config.retry_attempts = 2          # retries for timeouts, never for refusals
  config.verify_ssl = true
  config.socket_read_timeout = 15
  config.popular_tlds = %w[.com .net .org .info]
  config.instrumentation = ->(event) { Rails.logger.info(event) }
end
```

## Architecture

Five collaborators, each replaceable, wired together by `Client`:

```
Client
├── Registry::ServerRegistry   which server serves this TLD, and where the name splits
├── Transport::Factory         how to talk to it  (Strategy + Decorator)
├── Availability::Analyzer     what the answer means  (Chain of Responsibility)
├── Parser::Selector           what the record says  (Adapter)
└── Referral::Follower         thin-registry second hop
```

`Client` owns the sequence and none of the policy. Every collaborator arrives by
constructor injection, which is why the whole test suite runs offline against a
one-method fake transport.

### Detection is a chain of rules

Each rule answers one question and either returns a `Verdict` or `nil` for "not mine,
ask the next one". Two invariants hold the order together:

1. Rules that recognise a **non-answer** run first, so nothing reaching the permissive
   rules could have been a refusal or a wrong-server reply.
2. Every rule concluding `:registered` runs before every rule concluding `:available`,
   so when signals conflict the safe one wins.

| # | Rule | Verdict |
|---|---|---|
| 1 | `server_refusal` — rate limit, blocked client, retired port 43, HTTP error | `:unknown` |
| 2 | `wrong_registry` — unsupported TLD, or an address registry's banner | `:unknown` |
| 3 | `rdap_object` — structured JSON: `objectClassName` vs `errorCode` 404 | `:registered` / `:available` |
| 4 | `premium_name` | `:premium` |
| 5 | `explicit_unavailability` — general and per-TLD "registered" wording | `:registered` |
| 6 | `registration_fields` — three or more record fields present | `:registered` |
| 7 | `registry_marker` — the TLD's configured not-found string | `:available` |
| 8 | `availability_keywords` — multilingual not-found phrases | `:available` |
| 9 | `no_match` — the whitespace-tolerant regexp forms | `:available` |
| 10 | `tld_specific` — per-TLD availability wording | `:available` |
| 11 | `status_field` — an explicit `status: available` | `:available` |
| 12 | `recordless` — no record and no refusal; opt-in per TLD | `:available` |
| — | nothing matched | `:unknown` |

Adding support for a registry that invents new wording means one small object:

```ruby
class AcmeRule < MonoVM::Whois::Availability::Rule
  def call(context)
    return nil unless context.lower.include?("acme says this name is free")

    available(reason: "ACME wording")
  end
end

MonoVM::Whois.configure do |config|
  config.rules.insert_before("registry_marker", AcmeRule.new)
end
```

`RuleSet` also supports `prepend`, `append`, `insert_after`, `replace` and `remove`.

### RDAP first

For any TLD with an RDAP endpoint the client queries RDAP before port 43. RDAP answers
in structured JSON — a registered domain is an object with an `objectClassName`, an
unregistered one is an error document with `errorCode` 404 — so availability is *read*
rather than inferred from prose. Port 43 is the fallback, used whenever a TLD has no
RDAP endpoint or its RDAP endpoint fails.

TLD coverage comes from two bundled data files:

- `data/whois_servers.json` — a curated port 43 server list, 872 TLDs, with the
  registry's not-found marker per TLD.
- `data/rdap_bootstrap.json` — a snapshot of the IANA RDAP bootstrap registry
  (RFC 7484), ~1,200 TLDs. Refresh with `rake data:refresh_rdap`.

Definitions merge, so a TLD can get its port 43 host from one file and its RDAP URL
from the other. A deployment can correct a stale entry without waiting for a release:

```sh
export MONOVM_WHOIS_DEFINITIONS=/etc/monovm/whois-overrides.json
```

```json
[
  {
    "extensions": ".example,.test",
    "uri": "socket://whois.example.test",
    "available": "Domain not found",
    "rdap": "https://rdap.example.test/domain/"
  }
]
```

### Referral following

Thin registries hold almost nothing. Query `.com` and Verisign returns a name, a
status, nameservers and a pointer: `Registrar WHOIS Server:`. The registrant and often
the accurate expiry date only exist on that second server, so the client follows the
pointer one hop.

A referral enriches the **record** and never the **verdict**. The registry is
authoritative about whether a name exists, and a registrar's server that is down must
not be able to turn a registered domain into an available one.

### Punycode

Internationalised names are converted with an RFC 3492 implementation in
`MonoVM::Whois::Punycode`, verified against the RFC's own test vectors and the
published ACE forms of the IDN ccTLDs. It lives here rather than in a dependency to
keep the gem dependency-free.

Registries are queried in Punycode by default, because Verisign answers "No match" to
a UTF-8 query — which would read as availability. DENIC is the documented exception and
is sent the Unicode form over port 43 (`config.unicode_query_tlds`).

## Fail-safe classifications

Situations that a permissive heuristic reads as "available", and what this gem
reports instead — every choice points the same way, refusing to guess:

| Situation | Permissive heuristic | This gem |
|---|---|---|
| Rate-limit notice | `available` | `:unknown` |
| Client blocked / port 43 retired | `available` | `:unknown` |
| HTTP 403/429/5xx from RDAP | `available` | `:unknown` |
| Empty response | `available` | `:unknown` |
| Address registry reached by mistake | `available` | `:unknown` |
| Fewer than 2 registration fields | `available` | `:unknown` unless the TLD opts in |
| DENIC `Status: invalid` | `available` | `:registered` |
| Premium/reserved name | `available` | `:premium` |
| Dot-padded keys (`status....: Registered`) | `available` | `:registered` |
| Registry restriction notice | `available` | `:registered` |

## Development

```sh
bundle install
bundle exec rspec          # the offline suite
bundle exec rubocop
rake                       # both

rake spec_network          # live registry lookups, opt-in
rake data:refresh_rdap     # re-snapshot the IANA bootstrap
COVERAGE=1 bundle exec rspec
```

The offline suite never touches the network: HTTP is blocked by WebMock, and the
socket transport is exercised against a loopback server the spec starts itself.

## License

MIT. See [LICENSE](LICENSE).
