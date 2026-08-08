# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Registry::ServerRegistry do
  describe "#resolve" do
    subject(:registry) { stub_registry(".com" => {}, ".uk" => {}, ".co.uk" => {}, ".xn--fiqs8s" => {}) }

    it "splits a simple name" do
      resolution = registry.resolve("example.com")

      expect(resolution.sld).to eq("example")
      expect(resolution.tld).to eq(".com")
    end

    it "prefers the longest known suffix" do
      # The whole reason resolution is longest-first: ".co.uk" is a registrable
      # suffix, so "example.co.uk" must not resolve as SLD "co" under ".uk".
      resolution = registry.resolve("example.co.uk")

      expect(resolution.tld).to eq(".co.uk")
      expect(resolution.sld).to eq("example")
    end

    it "drops a subdomain and resolves to the registrable name" do
      resolution = registry.resolve("www.example.co.uk")

      expect(resolution.tld).to eq(".co.uk")
      expect(resolution.sld).to eq("example")
      expect(resolution.registrable.to_s).to eq("example.co.uk")
    end

    it "drops several levels of subdomain" do
      resolution = registry.resolve("a.b.c.example.com")

      expect(resolution.registrable.to_s).to eq("example.com")
    end

    it "matches an internationalised TLD through its ASCII form" do
      resolution = registry.resolve("例え.中国")

      expect(resolution.tld).to eq(".xn--fiqs8s")
      expect(resolution.query).to eq("xn--r8jz45g.xn--fiqs8s")
    end

    it "returns nil for an unknown suffix" do
      expect(registry.resolve("example.nowhere")).to be_nil
    end

    it "returns nil for a bare name with no TLD" do
      expect(registry.resolve("monovm")).to be_nil
    end

    it "accepts a DomainName as well as a String" do
      name = MonoVM::Whois::DomainName.parse("example.com")

      expect(registry.resolve(name).tld).to eq(".com")
    end

    it "carries the definition through, so the caller gets the endpoint too" do
      resolution = registry.resolve("example.com")

      expect(resolution.definition.tld).to eq(".com")
      expect(resolution.definition.whois_endpoint.host).to eq("whois.com.test")
    end
  end

  describe "#supports?" do
    subject(:registry) { stub_registry(".com" => {}) }

    it "accepts a dotted TLD" do
      expect(registry.supports?(".com")).to be(true)
    end

    it "accepts an undotted TLD" do
      expect(registry.supports?("com")).to be(true)
    end

    it "is case insensitive" do
      expect(registry.supports?(".COM")).to be(true)
    end

    it "is false for an unknown TLD" do
      expect(registry.supports?(".nowhere")).to be(false)
    end

    it "is false for nil" do
      expect(registry.supports?(nil)).to be(false)
    end
  end

  describe "source precedence" do
    it "lets a later source override an earlier one" do
      first = StubSource.new(
        ".com" => MonoVM::Whois::Registry::Definition.new(
          tld: ".com",
          whois_endpoint: MonoVM::Whois::Endpoint.parse("socket://old.test"),
          available_match: "old marker",
          sources: ["first"]
        )
      )
      second = StubSource.new(
        ".com" => MonoVM::Whois::Registry::Definition.new(
          tld: ".com",
          whois_endpoint: MonoVM::Whois::Endpoint.parse("socket://new.test"),
          sources: ["second"]
        )
      )

      registry = described_class.new(sources: [first, second])
      definition = registry.definition_for(".com")

      expect(definition.whois_endpoint.host).to eq("new.test")
      # Fields the later source did not set survive from the earlier one, which is
      # what lets the IANA bootstrap add RDAP without discarding curated markers.
      expect(definition.available_match).to eq("old marker")
      expect(definition.sources).to eq(%w[first second])
    end

    it "merges an RDAP endpoint onto a WHOIS-only definition" do
      whois_only = StubSource.new(
        ".com" => MonoVM::Whois::Registry::Definition.new(
          tld: ".com",
          whois_endpoint: MonoVM::Whois::Endpoint.parse("socket://whois.test"),
          sources: ["bundled"]
        )
      )
      rdap_only = StubSource.new(
        ".com" => MonoVM::Whois::Registry::Definition.new(
          tld: ".com",
          rdap_endpoint: MonoVM::Whois::Endpoint.parse("https://rdap.test/domain/"),
          sources: ["iana-rdap"]
        )
      )

      definition = described_class.new(sources: [whois_only, rdap_only]).definition_for(".com")

      expect(definition).to be_whois
      expect(definition).to be_rdap
      expect(definition.endpoints(prefer: :rdap).first.host).to eq("rdap.test")
      expect(definition.endpoints(prefer: :whois).first.host).to eq("whois.test")
    end

    it "raises when no source yields anything" do
      registry = described_class.new(sources: [StubSource.new({})])

      expect { registry.definitions }.to raise_error(MonoVM::Whois::DefinitionsError)
    end

    it "requires at least one source" do
      expect { described_class.new(sources: []) }.to raise_error(ArgumentError)
    end
  end

  describe "the bundled data" do
    subject(:registry) { described_class.default(override_path: nil) }

    it "covers a large number of TLDs" do
      # The bundled WHOIS list plus the IANA RDAP bootstrap. If this collapses, a
      # data file failed to load and most lookups would start returning :invalid.
      expect(registry.size).to be > 1_000
    end

    it "knows the common gTLDs" do
      expect(registry.supports?(".com")).to be(true)
      expect(registry.supports?(".net")).to be(true)
      expect(registry.supports?(".org")).to be(true)
    end

    it "knows multi-label suffixes" do
      expect(registry.supports?(".co.uk")).to be(true)
    end

    it "gives .com both a WHOIS and an RDAP endpoint" do
      definition = registry.definition_for(".com")

      expect(definition).to be_whois
      expect(definition).to be_rdap
    end

    it "prefers RDAP for .com by default" do
      definition = registry.definition_for(".com")

      expect(definition.endpoints(prefer: :rdap).first).to be_http
    end

    it "resolves a real multi-label name correctly" do
      expect(registry.resolve("bbc.co.uk").tld).to eq(".co.uk")
    end

    it "records which source supplied each definition" do
      expect(registry.definition_for(".com").sources).to include("bundled")
    end

    it "only keeps definitions that have somewhere to send a query" do
      expect(registry.definitions.values).to all(be_usable)
    end
  end

  describe "#reload" do
    it "re-reads the sources" do
      source = StubSource.new(
        ".com" => MonoVM::Whois::Registry::Definition.new(
          tld: ".com", whois_endpoint: MonoVM::Whois::Endpoint.parse("socket://a.test")
        )
      )
      registry = described_class.new(sources: [source])
      registry.definitions

      allow(source).to receive(:load).and_call_original
      registry.reload.definitions

      expect(source).to have_received(:load)
    end
  end
end
