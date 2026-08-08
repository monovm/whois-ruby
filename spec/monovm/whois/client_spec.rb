# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Client do
  describe "#lookup" do
    it "reports a registered domain" do
      body = <<~TEXT
        Domain Name: example.com
        Registrar: Example Registrar
        Creation Date: 2010-01-01T00:00:00Z
        Name Server: ns1.example.com
      TEXT

      result = stub_client({ "example.com" => body }).lookup("example.com")

      expect(result).to be_registered
      expect(result.tld).to eq(".com")
      expect(result.sld).to eq("example")
      expect(result.record.registrar).to eq("Example Registrar")
    end

    it "reports an available domain" do
      result = stub_client({ "free.com" => "No match for FREE.COM" }).lookup("free.com")

      expect(result).to be_available
      expect(result.record).to be_nil
    end

    it "reports unknown when the server refuses" do
      result = stub_client({ "x.com" => "Query limit exceeded, try again later." }).lookup("x.com")

      expect(result).to be_unknown
      expect(result).not_to be_available
    end

    it "reports unknown, not available, when the transport fails" do
      # The distinction the PHP package loses. A timeout is not a free domain.
      client = stub_client({ "x.com" => MonoVM::Whois::TimeoutError })

      result = client.lookup("x.com")

      expect(result).to be_unknown
      expect(result.reason).to include("scripted failure")
    end

    it "reports invalid for a malformed name without contacting anything" do
      transport = FakeTransport.new
      result = stub_client(transport).lookup("not a domain!")

      expect(result).to be_invalid
      expect(transport.call_count).to eq(0)
    end

    it "reports invalid for an unknown TLD" do
      result = stub_client({}).lookup("example.nowhere")

      expect(result).to be_invalid
      expect(result.reason).to include("no WHOIS or RDAP server")
    end

    it "reports invalid for a bare name, pointing at Checker" do
      result = stub_client({}).lookup("monovm")

      expect(result).to be_invalid
      expect(result.reason).to include("Checker")
    end

    it "queries the registrable name, dropping any subdomain" do
      transport = FakeTransport.new(default: "No match")
      stub_client(transport, tlds: { ".com" => {} }).lookup("www.example.com")

      expect(transport.calls.first[:query]).to eq("example.com")
    end

    it "queries in punycode by default" do
      transport = FakeTransport.new(default: "No match")
      stub_client(transport, tlds: { ".com" => {} }).lookup("münchen.com")

      expect(transport.calls.first[:query]).to eq("xn--mnchen-3ya.com")
    end

    it "queries in Unicode for the registries that require it" do
      # DENIC answers "Status: invalid" for the punycode form but resolves the
      # Unicode one. Everyone else is the reverse, hence the short exception list.
      config = no_middleware_config
      config.unicode_query_tlds = [".de"]

      transport = FakeTransport.new(default: "Status: free")
      client = stub_client(transport, tlds: { ".de" => {} }, config: config)
      client.lookup("münchen.de")

      expect(transport.calls.first[:query]).to eq("münchen.de")
    end
  end

  describe "endpoint preference" do
    let(:tlds) { { ".com" => { whois: "socket://whois.test", rdap: "https://rdap.test/domain/" } } }

    it "tries RDAP first by default" do
      transport = FakeTransport.new(default: "No match")
      stub_client(transport, tlds: tlds).lookup("example.com")

      expect(transport.calls.first[:endpoint]).to eq("https://rdap.test/domain/")
    end

    it "tries WHOIS first when asked" do
      config = no_middleware_config
      config.prefer = :whois

      transport = FakeTransport.new(default: "No match")
      stub_client(transport, tlds: tlds, config: config).lookup("example.com")

      expect(transport.calls.first[:endpoint]).to eq("socket://whois.test")
    end

    it "falls back to the second endpoint when the first fails" do
      # A TLD can have an RDAP entry in the IANA bootstrap whose endpoint is broken.
      # Falling through to port 43 is what keeps those TLDs answerable.
      transport = FakeTransport.new({
                                      "https://rdap.test/domain/" => MonoVM::Whois::ConnectionError,
                                      "socket://whois.test" => "No match for EXAMPLE.COM"
                                    })
      allow(transport).to receive(:fetch).and_call_original

      result = stub_client(transport, tlds: tlds).lookup("example.com")

      expect(result).to be_available
      expect(transport.call_count).to eq(2)
    end

    it "reports the preferred endpoint's failure when both fail" do
      timed_out = MonoVM::Whois::TimeoutError.new("rdap timed out")
      refused = MonoVM::Whois::ConnectionError.new("socket refused")
      transport = FakeTransport.new({
                                      "https://rdap.test/domain/" => timed_out,
                                      "socket://whois.test" => refused
                                    })

      result = stub_client(transport, tlds: tlds).lookup("example.com")

      expect(result).to be_unknown
      expect(result.reason).to eq("rdap timed out")
    end
  end

  describe "RDAP results" do
    let(:tlds) { { ".com" => { rdap: "https://rdap.test/domain/" } } }

    it "reads a domain object as registered" do
      document = {
        "objectClassName" => "domain",
        "ldhName" => "example.com",
        "handle" => "1",
        "status" => ["active"]
      }

      result = stub_client({ "example.com" => document }, tlds: tlds).lookup("example.com")

      expect(result).to be_registered
      expect(result.verdict.rule).to eq("rdap_object")
    end

    it "reads a 404 error document as available" do
      transport = FakeTransport.new(
        { "example.com" => { "errorCode" => 404, "title" => "Domain not found" } },
        status: 404
      )

      result = stub_client(transport, tlds: tlds).lookup("example.com")

      expect(result).to be_available
    end
  end

  describe "premium names" do
    it "reports premium rather than available" do
      tlds = { ".shop" => { premium_match: "Premium Name" } }
      transport = FakeTransport.new({ "example.shop" => "This is a Premium Name, not for sale." })

      result = stub_client(transport, tlds: tlds).lookup("example.shop")

      expect(result).to be_premium
      expect(result).not_to be_available
    end
  end

  describe "#available?" do
    it "is true only for a positive availability verdict" do
      expect(stub_client({ "a.com" => "No match for A.COM" }).available?("a.com")).to be(true)
    end

    it "is false for a refusal" do
      expect(stub_client({ "a.com" => "Rate limited, try again later" }).available?("a.com"))
        .to be(false)
    end

    it "is false for a registered domain" do
      body = "Domain Name: a.com\nRegistrar: X\nCreation Date: 2010-01-01\n"

      expect(stub_client({ "a.com" => body }).available?("a.com")).to be(false)
    end
  end

  describe "#explain" do
    it "returns the rule that decided and the whole trace" do
      explanation = stub_client({ "a.com" => "No match for A.COM" }).explain("a.com")

      expect(explanation[:status]).to eq(:available)
      expect(explanation[:trace]).to be_an(Array)
      expect(explanation[:trace].map { |entry| entry[:rule] }).to include("server_refusal")
      expect(explanation[:trace].last[:matched]).to be(true)
    end
  end

  describe "referral following" do
    let(:tlds) { { ".com" => { whois: "socket://whois.verisign.test" } } }

    let(:thin_record) do
      <<~TEXT
        Domain Name: EXAMPLE.COM
        Registry Domain ID: 1
        Registrar: Example Registrar
        Registrar WHOIS Server: whois.registrar.test
        Creation Date: 1995-08-14T04:00:00Z
        Name Server: ns1.example.com
      TEXT
    end

    let(:fat_record) do
      <<~TEXT
        Domain Name: EXAMPLE.COM
        Registrar: Example Registrar
        Registrant Name: Alice Example
        Registrant Email: alice@example.test
        Creation Date: 1995-08-14T04:00:00Z
      TEXT
    end

    it "fills in the registrant from the registrar's server" do
      transport = FakeTransport.new(default: thin_record)
      calls = []
      allow(transport).to receive(:fetch) do |query:, endpoint:|
        calls << endpoint.host
        body = endpoint.host == "whois.registrar.test" ? fat_record : thin_record
        MonoVM::Whois::Response.new(body: body, endpoint: endpoint, query: query)
      end

      config = no_middleware_config
      config.follow_referrals = true

      client = described_class.new(
        config: config,
        server_registry: stub_registry(tlds),
        transport_factory: FakeTransportFactory.new(transport),
        follower: MonoVM::Whois::Referral::Follower.new(
          transport_factory: FakeTransportFactory.new(transport)
        )
      )

      result = client.lookup("example.com")

      expect(calls).to eq(%w[whois.verisign.test whois.registrar.test])
      expect(result.record.registrant).to eq("Alice Example")
      # The registry stays authoritative for status and dates.
      expect(result).to be_registered
      expect(result.record.created_on).to eq(Time.utc(1995, 8, 14, 4, 0, 0))
    end

    it "keeps the registry verdict when the referral fails" do
      transport = FakeTransport.new(default: thin_record)
      allow(transport).to receive(:fetch) do |query:, endpoint:|
        raise MonoVM::Whois::ConnectionError, "down" if endpoint.host == "whois.registrar.test"

        MonoVM::Whois::Response.new(body: thin_record, endpoint: endpoint, query: query)
      end

      config = no_middleware_config
      config.follow_referrals = true

      client = described_class.new(
        config: config,
        server_registry: stub_registry(tlds),
        transport_factory: FakeTransportFactory.new(transport),
        follower: MonoVM::Whois::Referral::Follower.new(
          transport_factory: FakeTransportFactory.new(transport)
        )
      )

      expect(client.lookup("example.com")).to be_registered
    end
  end
end
