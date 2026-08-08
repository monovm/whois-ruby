# frozen_string_literal: true

require "tmpdir"

RSpec.describe MonoVM::Whois::Registry::Sources do
  describe MonoVM::Whois::Registry::Sources::JsonFile do
    def with_file(content)
      Dir.mktmpdir do |dir|
        path = File.join(dir, "servers.json")
        File.write(path, content)
        yield path
      end
    end

    it "expands a comma-separated extension list into one definition per TLD" do
      with_file(<<~JSON) do |path|
        [{"extensions": ".com,.net", "uri": "socket://whois.test", "available": "No match for"}]
      JSON
        definitions = described_class.new(path: path).load

        expect(definitions.keys).to eq([".com", ".net"])
        expect(definitions[".com"].available_match).to eq("No match for")
        expect(definitions[".net"].whois_endpoint.host).to eq("whois.test")
      end
    end

    it "normalises extensions written without a dot or in upper case" do
      with_file('[{"extensions": "COM, .Net ", "uri": "socket://a.test"}]') do |path|
        expect(described_class.new(path: path).load.keys).to eq([".com", ".net"])
      end
    end

    it "keys an internationalised TLD by its ASCII form" do
      with_file('[{"extensions": ".中国", "uri": "socket://a.test"}]') do |path|
        expect(described_class.new(path: path).load.keys).to eq([".xn--fiqs8s"])
      end
    end

    it "reads an RDAP endpoint alongside the socket one" do
      with_file(<<~JSON) do |path|
        [{"extensions": ".com", "uri": "socket://a.test", "rdap": "https://rdap.test/domain/"}]
      JSON
        definition = described_class.new(path: path).load[".com"]

        expect(definition).to be_whois
        expect(definition).to be_rdap
      end
    end

    it "reads available_when_empty as a boolean or a string" do
      with_file(<<~JSON) do |path|
        [{"extensions": ".a", "uri": "socket://a.test", "available_when_empty": true},
         {"extensions": ".b", "uri": "socket://b.test", "available_when_empty": "yes"},
         {"extensions": ".c", "uri": "socket://c.test", "available_when_empty": "0"}]
      JSON
        definitions = described_class.new(path: path).load

        expect(definitions[".a"]).to be_available_when_empty
        expect(definitions[".b"]).to be_available_when_empty
        expect(definitions[".c"]).not_to be_available_when_empty
      end
    end

    it "skips an entry with no endpoint at all" do
      with_file('[{"extensions": ".a"}, {"extensions": ".b", "uri": "socket://b.test"}]') do |path|
        expect(described_class.new(path: path).load.keys).to eq([".b"])
      end
    end

    it "raises for a missing required file" do
      expect { described_class.new(path: "/nonexistent/servers.json").load }
        .to raise_error(MonoVM::Whois::DefinitionsError, /not found/)
    end

    it "returns nothing for a missing optional file" do
      expect(described_class.new(path: "/nonexistent.json", optional: true).load).to eq({})
    end

    it "raises for malformed JSON" do
      with_file("{not json") do |path|
        expect { described_class.new(path: path).load }
          .to raise_error(MonoVM::Whois::DefinitionsError, /not valid JSON/)
      end
    end

    it "raises when the top level is not an array" do
      with_file('{"extensions": ".com"}') do |path|
        expect { described_class.new(path: path).load }
          .to raise_error(MonoVM::Whois::DefinitionsError, /JSON array/)
      end
    end

    it "names the offending entry when an endpoint is unusable" do
      with_file('[{"extensions": ".a", "uri": "gopher://a.test"}]') do |path|
        expect { described_class.new(path: path).load }
          .to raise_error(MonoVM::Whois::DefinitionsError, /entry 0/)
      end
    end

    describe "the bundled server list" do
      subject(:definitions) { described_class.new(path: MonoVM::Whois::Paths::WHOIS_SERVERS).load }

      it "loads several hundred TLDs" do
        expect(definitions.size).to be > 800
      end

      it "gives every definition a usable endpoint" do
        expect(definitions.values).to all(be_usable)
      end

      it "carries the not-found marker for .com" do
        expect(definitions[".com"].available_match).to eq("No match for")
      end

      it "covers multi-label suffixes" do
        expect(definitions).to have_key(".co.uk")
      end
    end
  end

  describe MonoVM::Whois::Registry::Sources::IanaBootstrap do
    it "turns a bootstrap service entry into an RDAP endpoint" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "dns.json")
        File.write(path, JSON.generate(
                           "version" => "1.0",
                           "publication" => "2026-07-23T02:00:03Z",
                           "services" => [[%w[com net], ["https://rdap.verisign.com/com/v1/"]]]
                         ))

        definitions = described_class.new(path: path).load

        # RFC 7482 puts domain lookups under {base}/domain/{name}.
        expect(definitions[".com"].rdap_endpoint.to_s)
          .to eq("https://rdap.verisign.com/com/v1/domain/")
        expect(definitions[".net"]).to be_rdap
        expect(definitions[".com"]).not_to be_whois
      end
    end

    it "adds the trailing slash when the registry omitted it" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "dns.json")
        File.write(path, JSON.generate(
                           "services" => [[["kg"], ["http://rdap.cctld.kg"]]]
                         ))

        expect(described_class.new(path: path).load[".kg"].rdap_endpoint.to_s)
          .to eq("http://rdap.cctld.kg/domain/")
      end
    end

    it "prefers HTTPS when a registry offers both" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "dns.json")
        File.write(path, JSON.generate(
                           "services" => [[["example"],
                                           ["http://rdap.test/", "https://rdap.test/"]]]
                         ))

        expect(described_class.new(path: path).load[".example"].rdap_endpoint).to be_tls
      end
    end

    it "skips a malformed entry without losing the others" do
      Dir.mktmpdir do |dir|
        path = File.join(dir, "dns.json")
        File.write(path, JSON.generate(
                           "services" => [
                             [["bad"], ["not a url at all"]],
                             [["good"], ["https://rdap.test/"]]
                           ]
                         ))

        expect(described_class.new(path: path).load).to have_key(".good")
      end
    end

    it "returns nothing when the snapshot is absent" do
      expect(described_class.new(path: "/nonexistent/dns.json").load).to eq({})
    end

    describe "the bundled snapshot" do
      subject(:source) { described_class.new }

      it "covers over a thousand TLDs" do
        expect(source.load.size).to be > 1_000
      end

      it "records when it was published, so staleness is visible" do
        expect(source.published_at).to match(/\A\d{4}-\d{2}-\d{2}/)
      end

      it "gives .com an RDAP endpoint ending in domain/" do
        expect(source.load[".com"].rdap_endpoint.to_s).to end_with("domain/")
      end

      it "attributes every definition to itself" do
        expect(source.load[".com"].sources).to eq(["iana-rdap"])
      end
    end
  end
end
