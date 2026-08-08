# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Checker do
  def checker_for(transport, tlds: { ".com" => {} }, **options)
    described_class.new(
      client: stub_client(transport, tlds: tlds),
      config: no_middleware_config,
      **options
    )
  end

  describe "#check" do
    it "checks a single domain" do
      transport = FakeTransport.new({ "example.com" => "No match for EXAMPLE.COM" })

      expect(checker_for(transport).check("example.com")).to eq("example.com" => :available)
    end

    it "checks a list" do
      transport = FakeTransport.new({
                                      "free.com" => "No match for FREE.COM",
                                      "taken.com" => "Domain Name: taken.com\n" \
                                                     "Registrar: X\nCreation Date: 2010-01-01\n"
                                    })

      expect(checker_for(transport).check(%w[free.com taken.com]))
        .to eq("free.com" => :available, "taken.com" => :registered)
    end

    it "expands a bare name across the popular TLDs" do
      transport = FakeTransport.new(default: "No match")
      results = checker_for(transport, tlds: { ".com" => {}, ".net" => {} },
                                       popular_tlds: %w[.com .net]).check("monovm")

      expect(results.keys).to eq(%w[monovm.com monovm.net])
    end

    it "accepts TLDs without a leading dot" do
      transport = FakeTransport.new(default: "No match")
      results = checker_for(transport, tlds: { ".com" => {} }, popular_tlds: %w[com]).check("monovm")

      expect(results.keys).to eq(["monovm.com"])
    end

    it "accepts a comma-separated TLD string" do
      transport = FakeTransport.new(default: "No match")
      results = checker_for(transport, tlds: { ".com" => {}, ".net" => {} },
                                       popular_tlds: ".com,.net").check("monovm")

      expect(results.keys).to eq(%w[monovm.com monovm.net])
    end

    it "looks a repeated name up only once" do
      transport = FakeTransport.new(default: "No match")
      checker_for(transport).check(["example.com", "EXAMPLE.COM", "https://example.com/path"])

      expect(transport.call_count).to eq(1)
    end

    it "preserves the order it was asked in" do
      transport = FakeTransport.new(default: "No match")
      names = %w[c.com a.com b.com]

      expect(checker_for(transport).check(names).keys).to eq(names)
    end

    it "marks an unresolvable name invalid without dropping the rest" do
      transport = FakeTransport.new(default: "No match for X")
      results = checker_for(transport).check(["example.com", "bad name!"])

      expect(results["example.com"]).to eq(:available)
      expect(results["bad name!"]).to eq(:invalid)
    end

    it "rejects a non-String entry" do
      expect { checker_for(FakeTransport.new).check([42]) }.to raise_error(ArgumentError)
    end

    it "rejects an empty TLD list" do
      expect { checker_for(FakeTransport.new, popular_tlds: []) }.to raise_error(ArgumentError)
    end

    it "returns an empty hash for an empty list" do
      expect(checker_for(FakeTransport.new).check([])).to eq({})
    end
  end

  describe "#check_detailed" do
    it "returns full results" do
      transport = FakeTransport.new({ "example.com" => "No match for EXAMPLE.COM" })
      results = checker_for(transport).check_detailed("example.com")

      expect(results["example.com"]).to be_a(MonoVM::Whois::Result)
      expect(results["example.com"].verdict.rule).to be_a(String)
    end
  end

  describe "concurrency" do
    it "runs lookups in parallel" do
      # Each lookup blocks until every worker has arrived, so this can only finish if
      # they genuinely overlap.
      names = %w[a.com b.com c.com d.com]
      barrier = Queue.new
      arrived = Queue.new

      transport = FakeTransport.new(default: "No match")
      allow(transport).to receive(:fetch) do |query:, endpoint:|
        arrived << query
        barrier.pop
        MonoVM::Whois::Response.new(body: "No match", endpoint: endpoint, query: query)
      end

      checker = checker_for(transport, concurrency: 4)
      thread = Thread.new { checker.check(names) }

      names.length.times { arrived.pop }
      names.length.times { barrier << :go }

      expect(thread.value.values).to all(eq(:available))
    end

    it "still works with concurrency of one" do
      transport = FakeTransport.new(default: "No match")

      expect(checker_for(transport, concurrency: 1).check(%w[a.com b.com]).values)
        .to all(eq(:available))
    end

    it "keeps the other answers when one lookup raises unexpectedly" do
      transport = FakeTransport.new(default: "No match")
      client = stub_client(transport)
      allow(client).to receive(:lookup).and_call_original
      allow(client).to receive(:lookup)
        .with(satisfy { |name| name.to_s == "boom.com" })
        .and_raise("unexpected")

      checker = described_class.new(client: client, config: no_middleware_config, concurrency: 2)
      results = checker.check(%w[boom.com fine.com])

      expect(results["boom.com"]).to eq(:unknown)
      expect(results["fine.com"]).to eq(:available)
    end
  end

  describe "option handling" do
    # Exercised through the option builder rather than through .whois, which would
    # perform real lookups.
    def build(options)
      described_class.send(:build_options, options)
    end

    it "accepts the PHP package's camelCase option name" do
      # Kept so code being ported from monovm/whois-php keeps working verbatim.
      checker = described_class.new(**build(popularTLDs: [".io"]))

      expect(checker.popular_tlds).to eq([".io"])
    end

    it "accepts the snake_case name too" do
      expect(described_class.new(**build(popular_tlds: [".dev"])).popular_tlds).to eq([".dev"])
    end

    it "routes anything else at the configuration" do
      expect(build(prefer: :whois)[:config].prefer).to eq(:whois)
    end

    it "passes concurrency through" do
      expect(described_class.new(**build(concurrency: 3)).concurrency).to eq(3)
    end

    it "rejects an unknown option rather than ignoring it" do
      expect { build(nonsense: true) }.to raise_error(ArgumentError, /nonsense/)
    end
  end
end
