# frozen_string_literal: true

# A definition source backed by a Hash, so specs need no files on disk.
class StubSource < MonoVM::Whois::Registry::Sources::Base
  def initialize(definitions)
    @definitions = definitions
    super()
  end

  def name
    "stub"
  end

  def load
    @definitions
  end
end

module StubRegistry
  # Build a registry covering just the TLDs a spec cares about.
  #
  #   stub_registry(".com" => { available_match: "No match for" },
  #                 ".co.uk" => {})
  def stub_registry(tlds)
    definitions = tlds.each_with_object({}) do |(tld, attributes), built|
      attributes ||= {}
      built[tld] = MonoVM::Whois::Registry::Definition.new(
        tld: tld,
        whois_endpoint: MonoVM::Whois::Endpoint.parse(
          attributes.fetch(:whois, "socket://whois#{tld}.test")
        ),
        rdap_endpoint: attributes[:rdap] && MonoVM::Whois::Endpoint.parse(attributes[:rdap]),
        available_match: attributes[:available_match],
        premium_match: attributes[:premium_match],
        available_when_empty: attributes.fetch(:available_when_empty, false),
        sources: ["stub"]
      )
    end

    MonoVM::Whois::Registry::ServerRegistry.new(sources: [StubSource.new(definitions)])
  end

  # A client wired to a fake transport and a stub registry.
  def stub_client(bodies, tlds: { ".com" => {} }, config: nil, **options)
    transport = bodies.is_a?(FakeTransport) ? bodies : FakeTransport.new(bodies, **options)

    MonoVM::Whois::Client.new(
      config: config || no_middleware_config,
      server_registry: stub_registry(tlds),
      transport_factory: FakeTransportFactory.new(transport),
      follower: nil
    )
  end

  # Timers and caches make assertions on call counts non-deterministic.
  def no_middleware_config
    config = MonoVM::Whois::Configuration.new
    config.cache = false
    config.throttle_interval = 0
    config.retry_attempts = 1
    config.follow_referrals = false
    config
  end
end

RSpec.configure do |config|
  config.include StubRegistry
end
