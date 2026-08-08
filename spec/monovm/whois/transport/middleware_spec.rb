# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Transport::Middleware do
  describe MonoVM::Whois::Transport::Middleware::Cache do
    let(:inner) { FakeTransport.new(default: "No match") }

    it "serves a repeated query without asking the transport again" do
      cache = described_class.new(inner, ttl: 60, clock: -> { 0 })

      2.times { cache.fetch(query: "a.com", endpoint: endpoint) }

      expect(inner.call_count).to eq(1)
    end

    it "keys on the endpoint as well as the query" do
      cache = described_class.new(inner, ttl: 60, clock: -> { 0 })

      cache.fetch(query: "a.com", endpoint: endpoint("socket://one.test"))
      cache.fetch(query: "a.com", endpoint: endpoint("socket://two.test"))

      expect(inner.call_count).to eq(2)
    end

    it "expires an entry once the TTL passes" do
      now = 0.0
      cache = described_class.new(inner, ttl: 10, clock: -> { now })

      cache.fetch(query: "a.com", endpoint: endpoint)
      now = 11.0
      cache.fetch(query: "a.com", endpoint: endpoint)

      expect(inner.call_count).to eq(2)
    end

    it "does not remember a failure" do
      # A transient timeout must not poison every later lookup of that name.
      flaky = FakeTransport.new({ "a.com" => MonoVM::Whois::TimeoutError })
      cache = described_class.new(flaky, ttl: 60, clock: -> { 0 })

      2.times do
        cache.fetch(query: "a.com", endpoint: endpoint)
      rescue MonoVM::Whois::TimeoutError
        nil
      end

      expect(flaky.call_count).to eq(2)
    end

    it "evicts the least recently used entry past the cap" do
      cache = described_class.new(inner, ttl: 600, max_entries: 2, clock: -> { 0 })

      cache.fetch(query: "a.com", endpoint: endpoint)
      cache.fetch(query: "b.com", endpoint: endpoint)
      cache.fetch(query: "a.com", endpoint: endpoint) # refreshes a.com
      cache.fetch(query: "c.com", endpoint: endpoint) # evicts b.com

      expect(cache.size).to eq(2)
      cache.fetch(query: "a.com", endpoint: endpoint)
      expect(inner.call_count).to eq(3)
    end
  end

  describe MonoVM::Whois::Transport::Middleware::Throttle do
    let(:inner) { FakeTransport.new(default: "No match") }

    it "does not delay the first query to a host" do
      slept = []
      throttle = described_class.new(inner, interval: 1.0, clock: -> { 0 },
                                            sleeper: ->(s) { slept << s })

      throttle.fetch(query: "a.com", endpoint: endpoint)

      expect(slept).to be_empty
    end

    it "waits between consecutive queries to the same host" do
      slept = []
      throttle = described_class.new(inner, interval: 1.0, clock: -> { 0 },
                                            sleeper: ->(s) { slept << s })

      3.times { throttle.fetch(query: "a.com", endpoint: endpoint) }

      # Slots are reserved at 0, 1 and 2 seconds; the clock never moves, so the waits
      # are the full interval each time.
      expect(slept).to eq([1.0, 2.0])
    end

    it "throttles per host, so a batch across registries still runs in parallel" do
      slept = []
      throttle = described_class.new(inner, interval: 1.0, clock: -> { 0 },
                                            sleeper: ->(s) { slept << s })

      throttle.fetch(query: "a.com", endpoint: endpoint("socket://one.test"))
      throttle.fetch(query: "a.net", endpoint: endpoint("socket://two.test"))

      expect(slept).to be_empty
    end
  end

  describe MonoVM::Whois::Transport::Middleware::Retry do
    it "retries a timeout" do
      attempts = 0
      flaky = lambda do |_query, _endpoint|
        attempts += 1
        raise MonoVM::Whois::TimeoutError, "slow" if attempts == 1

        "No match"
      end
      inner = FakeTransport.new({ "a.com" => flaky })

      retrier = described_class.new(inner, attempts: 2, backoff: 0, sleeper: ->(_s) {})
      response = retrier.fetch(query: "a.com", endpoint: endpoint)

      expect(response.text).to eq("No match")
      expect(attempts).to eq(2)
    end

    it "gives up after the configured number of attempts" do
      inner = FakeTransport.new({ "a.com" => MonoVM::Whois::ConnectionError })
      retrier = described_class.new(inner, attempts: 3, backoff: 0, sleeper: ->(_s) {})

      expect { retrier.fetch(query: "a.com", endpoint: endpoint) }
        .to raise_error(MonoVM::Whois::ConnectionError)
      expect(inner.call_count).to eq(3)
    end

    it "does not retry a refusal" do
      # A refusal usually *is* a rate limit; retrying makes the block worse and holds
      # up every other lookup in the batch behind the backoff.
      inner = FakeTransport.new({ "a.com" => MonoVM::Whois::ServerRefusedError.new("rate limited") })
      retrier = described_class.new(inner, attempts: 3, backoff: 0, sleeper: ->(_s) {})

      expect { retrier.fetch(query: "a.com", endpoint: endpoint) }
        .to raise_error(MonoVM::Whois::ServerRefusedError)
      expect(inner.call_count).to eq(1)
    end

    it "backs off exponentially" do
      slept = []
      inner = FakeTransport.new({ "a.com" => MonoVM::Whois::TimeoutError })
      retrier = described_class.new(inner, attempts: 3, backoff: 0.5, sleeper: ->(s) { slept << s })

      begin
        retrier.fetch(query: "a.com", endpoint: endpoint)
      rescue MonoVM::Whois::TimeoutError
        nil
      end

      expect(slept).to eq([0.5, 1.0])
    end
  end

  describe MonoVM::Whois::Transport::Middleware::Instrumentation do
    it "publishes a successful exchange" do
      events = []
      inner = FakeTransport.new(default: "No match")
      wrapped = described_class.new(inner, subscriber: ->(event) { events << event })

      wrapped.fetch(query: "a.com", endpoint: endpoint)

      expect(events.length).to eq(1)
      expect(events.first).to include(query: "a.com", outcome: :ok, host: "whois.example.test")
      expect(events.first[:elapsed]).to be_a(Float)
    end

    it "publishes a failure and re-raises" do
      events = []
      inner = FakeTransport.new({ "a.com" => MonoVM::Whois::TimeoutError })
      wrapped = described_class.new(inner, subscriber: ->(event) { events << event })

      expect { wrapped.fetch(query: "a.com", endpoint: endpoint) }
        .to raise_error(MonoVM::Whois::TimeoutError)
      expect(events.first).to include(outcome: :error, error: "MonoVM::Whois::TimeoutError")
    end

    it "survives a subscriber that raises" do
      # A broken metrics pipeline must never take a lookup down with it.
      inner = FakeTransport.new(default: "No match")
      wrapped = described_class.new(inner, subscriber: ->(_event) { raise "metrics down" })

      expect { wrapped.fetch(query: "a.com", endpoint: endpoint) }.not_to raise_error
    end
  end

  describe "composition" do
    it "stacks in the order the factory declares" do
      inner = FakeTransport.new(default: "No match")
      events = []

      factory = MonoVM::Whois::Transport::Factory.new(
        transports: [inner],
        middleware: [
          MonoVM::Whois::Transport::Middleware::Instrumentation.builder(
            subscriber: ->(event) { events << event }
          ),
          MonoVM::Whois::Transport::Middleware::Cache.builder(ttl: 60, clock: -> { 0 })
        ]
      )

      transport = factory.for(endpoint)
      2.times { transport.fetch(query: "a.com", endpoint: endpoint) }

      # The cache answered the second call, but instrumentation is outside it and saw
      # both — which is what you want from a metrics layer.
      expect(inner.call_count).to eq(1)
      expect(events.length).to eq(2)
    end

    it "reuses one wrapped transport, so middleware state persists across calls" do
      factory = MonoVM::Whois::Transport::Factory.new(
        transports: [FakeTransport.new(default: "No match")],
        middleware: [MonoVM::Whois::Transport::Middleware::Cache.builder(ttl: 60, clock: -> { 0 })]
      )

      # Asking twice must hand back the identical wrapper; a fresh one each time would
      # reset the cache and the throttle clock on every lookup.
      # rubocop:disable RSpec/IdenticalEqualityAssertion
      expect(factory.for(endpoint)).to be(factory.for(endpoint))
      # rubocop:enable RSpec/IdenticalEqualityAssertion
    end

    it "unwraps to the real transport" do
      inner = FakeTransport.new
      wrapped = MonoVM::Whois::Transport::Middleware::Cache.new(
        MonoVM::Whois::Transport::Middleware::Retry.new(inner)
      )

      expect(wrapped.unwrap).to be(inner)
    end
  end
end
