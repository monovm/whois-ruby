# frozen_string_literal: true

RSpec.describe MonoVM::Whois do
  describe "the module facade" do
    before do
      described_class.configure do |config|
        config.cache = false
        config.throttle_interval = 0
      end
    end

    it "exposes a version" do
      expect(described_class::VERSION).to match(/\A\d+\.\d+\.\d+/)
    end

    it "memoises one client, so definitions and caches are shared" do
      # Both sides are meant to be the same call: the assertion is that it returns
      # the identical object twice.
      # rubocop:disable RSpec/IdenticalEqualityAssertion
      expect(described_class.client).to be(described_class.client)
      # rubocop:enable RSpec/IdenticalEqualityAssertion
    end

    it "rebuilds the client after a configuration change" do
      first = described_class.client
      described_class.configure { |config| config.prefer = :whois }

      expect(described_class.client).not_to be(first)
      expect(described_class.client.config.prefer).to eq(:whois)
    end

    it "reports the supported TLD count from the bundled data" do
      expect(described_class.supported_tlds.length).to be > 1_000
    end

    it "answers whether a TLD is supported" do
      expect(described_class.supports?(".com")).to be(true)
      expect(described_class.supports?(".not-a-real-tld")).to be(false)
    end

    it "delegates lookup to the client" do
      client = instance_double(MonoVM::Whois::Client)
      allow(described_class).to receive(:client).and_return(client)
      allow(client).to receive(:lookup).with("example.com").and_return(:sentinel)

      expect(described_class.lookup("example.com")).to eq(:sentinel)
    end

    it "delegates available? to the client" do
      client = instance_double(MonoVM::Whois::Client)
      allow(described_class).to receive(:client).and_return(client)
      allow(client).to receive(:available?).with("example.com").and_return(true)

      expect(described_class.available?("example.com")).to be(true)
    end
  end

  describe "wiring, end to end but offline" do
    # Everything real except the socket: definitions, resolution, rule chain, parser.
    let(:registered_body) do
      <<~TEXT
        Domain Name: EXAMPLE.COM
        Registry Domain ID: 2336799_DOMAIN_COM-VRSN
        Registrar WHOIS Server: whois.registrar.test
        Registrar: Example Registrar, LLC
        Registrar IANA ID: 376
        Creation Date: 1995-08-14T04:00:00Z
        Registry Expiry Date: 2027-08-13T04:00:00Z
        Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        Name Server: NS1.EXAMPLE.COM
        Name Server: NS2.EXAMPLE.COM
        DNSSEC: unsigned
      TEXT
    end

    let(:transport) do
      FakeTransport.new({
                          "example.com" => registered_body,
                          "definitely-not-registered-xyzzy.com" =>
                            "No match for DEFINITELY-NOT-REGISTERED-XYZZY.COM"
                        })
    end

    let(:client) do
      config = MonoVM::Whois::Configuration.new
      config.cache = false
      config.throttle_interval = 0
      config.follow_referrals = false

      MonoVM::Whois::Client.new(
        config: config,
        transport_factory: FakeTransportFactory.new(transport),
        follower: nil
      )
    end

    it "resolves .com through the real bundled definitions" do
      result = client.lookup("example.com")

      expect(result.tld).to eq(".com")
      expect(result).to be_registered
    end

    it "parses the record with the ICANN parser it selected itself" do
      record = client.lookup("example.com").record

      expect(record.registrar).to eq("Example Registrar, LLC")
      expect(record.nameservers).to eq(%w[ns1.example.com ns2.example.com])
      expect(record.expires_on).to eq(Time.utc(2027, 8, 13, 4, 0, 0))
      expect(record).to be_transfer_prohibited
      expect(record).not_to be_dnssec
    end

    it "reports an unregistered name as available" do
      expect(client.lookup("definitely-not-registered-xyzzy.com")).to be_available
    end

    it "resolves a multi-label suffix through the real definitions" do
      allow(transport).to receive(:fetch) do |query:, endpoint:|
        MonoVM::Whois::Response.new(body: "No match", endpoint: endpoint, query: query)
      end

      expect(client.lookup("something.co.uk").tld).to eq(".co.uk")
    end
  end

  describe "custom rules" do
    it "lets a host application add a rule without forking the gem" do
      # The extension point the chain exists for: a registry invents new wording and
      # you need one small object, not a patch to the analyzer.
      custom = Class.new(MonoVM::Whois::Availability::Rule) do
        def name
          "acme_special"
        end

        def call(context)
          return nil unless context.lower.include?("acme says it is free")

          available(reason: "acme wording")
        end
      end

      config = MonoVM::Whois::Configuration.new
      config.cache = false
      config.throttle_interval = 0
      config.rules.prepend(custom.new)

      client = MonoVM::Whois::Client.new(
        config: config,
        server_registry: stub_registry(".com" => {}),
        transport_factory: FakeTransportFactory.new(
          FakeTransport.new({ "x.com" => "ACME says it is free" })
        ),
        follower: nil
      )

      result = client.lookup("x.com")

      expect(result).to be_available
      expect(result.verdict.rule).to eq("acme_special")
    end

    it "can insert a rule at a named position" do
      rules = MonoVM::Whois::Availability::RuleSet.default
      marker = Class.new(MonoVM::Whois::Availability::Rule) do
        def name
          "marker"
        end

        def call(_context)
          nil
        end
      end

      rules.insert_before("registry_marker", marker.new)

      expect(rules.names.index("marker")).to eq(rules.names.index("registry_marker") - 1)
    end

    it "refuses to insert against a rule that does not exist" do
      rules = MonoVM::Whois::Availability::RuleSet.default

      expect { rules.insert_before("nope", double) }.to raise_error(ArgumentError, /no rule named/)
    end

    it "can remove a shipped rule" do
      rules = MonoVM::Whois::Availability::RuleSet.default
      rules.remove("recordless")

      expect(rules.names).not_to include("recordless")
    end
  end
end
