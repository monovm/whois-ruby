# frozen_string_literal: true

RSpec.describe "value objects" do
  describe MonoVM::Whois::Endpoint do
    it "parses a bare socket endpoint with the default WHOIS port" do
      point = described_class.parse("socket://whois.nic.uk")

      expect(point.host).to eq("whois.nic.uk")
      expect(point.port).to eq(43)
      expect(point).to be_socket
      expect(point.kind).to eq(:whois)
    end

    it "parses an explicit port" do
      expect(described_class.parse("socket://host.test:4343").port).to eq(4343)
    end

    it "tolerates a trailing slash, which some definition files carry" do
      expect(described_class.parse("socket://host.test/").host).to eq("host.test")
    end

    it "parses an HTTPS endpoint" do
      point = described_class.parse("https://rdap.test/domain/")

      expect(point).to be_http
      expect(point).to be_tls
      expect(point.kind).to eq(:rdap)
      expect(point.port).to eq(443)
    end

    it "builds a URL by appending the name" do
      point = described_class.parse("https://rdap.test/domain/")

      expect(point.url_for("example.com")).to eq("https://rdap.test/domain/example.com")
    end

    it "substitutes a placeholder when the endpoint has one" do
      point = described_class.parse("https://rdap.test/lookup?name={domain}&f=json")

      expect(point.url_for("example.com")).to eq("https://rdap.test/lookup?name=example.com&f=json")
    end

    it "refuses to build a URL for a socket endpoint" do
      expect { described_class.parse("socket://a.test").url_for("x.com") }
        .to raise_error(MonoVM::Whois::DefinitionsError)
    end

    it "rejects an empty endpoint" do
      expect { described_class.parse("") }.to raise_error(MonoVM::Whois::DefinitionsError)
    end

    it "rejects an unknown scheme" do
      expect { described_class.parse("gopher://a.test") }
        .to raise_error(MonoVM::Whois::DefinitionsError, /unsupported endpoint scheme/)
    end

    it "compares by URI" do
      # Two separately built endpoints with the same URI must be ==. Identical
      # expressions are the point of a value-equality test.
      # rubocop:disable RSpec/IdenticalEqualityAssertion
      expect(described_class.parse("socket://a.test")).to eq(described_class.parse("socket://a.test"))
      # rubocop:enable RSpec/IdenticalEqualityAssertion
    end
  end

  describe MonoVM::Whois::Response do
    it "normalises line endings in #text but keeps #body verbatim" do
      response = whois_response("a\r\nb\rc\n")

      expect(response.text).to eq("a\nb\nc\n")
      expect(response.body).to eq("a\r\nb\rc\n")
    end

    it "parses a JSON body" do
      expect(rdap_response({ "a" => 1 }).json).to eq("a" => 1)
    end

    it "returns nil rather than raising for a non-JSON body" do
      expect(whois_response("Domain Name: a.com").json).to be_nil
    end

    it "returns nil for a JSON array, since RDAP objects are documents" do
      expect(rdap_response("[1,2]").json).to be_nil
    end

    it "knows when it is empty" do
      expect(whois_response("   \n ")).to be_empty
    end

    it "replaces invalid bytes instead of raising" do
      response = whois_response("valid \xFF\xFE bytes".b)

      expect { response.text }.not_to raise_error
    end

    it "freezes the body" do
      expect(whois_response("a").body).to be_frozen
    end
  end

  describe MonoVM::Whois::Availability::Verdict do
    it "exposes each status as a predicate" do
      expect(described_class.available).to be_available
      expect(described_class.registered).to be_registered
      expect(described_class.premium).to be_premium
      expect(described_class.unknown).to be_unknown
    end

    it "treats unknown as inconclusive and the rest as conclusive" do
      expect(described_class.unknown).not_to be_conclusive
      expect(described_class.available).to be_conclusive
      expect(described_class.premium).to be_conclusive
    end

    it "rejects a status outside the four" do
      expect { described_class.new(status: :maybe) }.to raise_error(ArgumentError)
    end

    it "attaches a trace without mutating the original" do
      original = described_class.available(rule: "no_match")
      traced = original.with_trace([{ rule: "no_match", matched: true }])

      expect(original.trace).to be_empty
      expect(traced.trace.length).to eq(1)
      expect(traced.rule).to eq("no_match")
    end

    it "is frozen" do
      expect(described_class.available).to be_frozen
    end
  end

  describe MonoVM::Whois::Result do
    let(:name) { MonoVM::Whois::DomainName.parse("example.com") }

    it "adds :invalid to the verdict statuses, for names that never reached a server" do
      result = described_class.invalid(name, reason: "no server known")

      expect(result).to be_invalid
      expect(result).not_to be_conclusive
      expect(result.whois_message).to eq("no server known")
    end

    it "distinguishes unknown from invalid" do
      result = described_class.unknown(name, reason: "rate limited")

      expect(result).to be_unknown
      expect(result).not_to be_invalid
      expect(result.verdict).to be_unknown
    end

    it "rejects an unknown status" do
      expect { described_class.new(domain: name, status: :maybe) }.to raise_error(ArgumentError)
    end

    it "serialises without nils" do
      result = described_class.new(domain: name, status: :available, tld: ".com", sld: "example")

      expect(result.to_h).to eq(domain: "example.com", status: :available, tld: ".com", sld: "example")
    end
  end

  describe MonoVM::Whois::Registry::Definition do
    it "orders endpoints by preference" do
      whois = MonoVM::Whois::Endpoint.parse("socket://whois.test")
      rdap = MonoVM::Whois::Endpoint.parse("https://rdap.test/domain/")
      subject = described_class.new(tld: ".com", whois_endpoint: whois, rdap_endpoint: rdap)

      expect(subject.endpoints(prefer: :rdap)).to eq([rdap, whois])
      expect(subject.endpoints(prefer: :whois)).to eq([whois, rdap])
    end

    it "omits an endpoint it does not have" do
      subject = described_class.new(
        tld: ".com", whois_endpoint: MonoVM::Whois::Endpoint.parse("socket://a.test")
      )

      expect(subject.endpoints.length).to eq(1)
    end

    it "is unusable with no endpoint at all" do
      expect(described_class.new(tld: ".com")).not_to be_usable
    end

    it "treats an empty marker as absent" do
      expect(described_class.new(tld: ".com", available_match: "  ").available_match).to be_nil
    end
  end
end
