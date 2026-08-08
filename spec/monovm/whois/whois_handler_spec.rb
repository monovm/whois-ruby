# frozen_string_literal: true

RSpec.describe MonoVM::Whois::WhoisHandler do
  def handler_for(body, domain: "example.com", tlds: { ".com" => {} })
    described_class.new(domain, client: stub_client({ domain => body }, tlds: tlds))
  end

  let(:registered_body) do
    <<~TEXT
      Domain Name: EXAMPLE.COM
      Registrar: Example Registrar
      Creation Date: 2010-01-01T00:00:00Z
      Registry Expiry Date: 2027-01-01T00:00:00Z
      Name Server: ns1.example.com
    TEXT
  end

  describe "a registered domain" do
    subject(:handler) { handler_for(registered_body) }

    it "is not available" do
      expect(handler).not_to be_available
    end

    it "is registered" do
      expect(handler).to be_registered
    end

    it "is valid" do
      expect(handler).to be_valid
    end

    it "exposes the TLD and SLD" do
      expect(handler.tld).to eq(".com")
      expect(handler.sld).to eq("example")
    end

    it "exposes the raw registry response" do
      expect(handler.whois_message).to include("Domain Name: EXAMPLE.COM")
    end

    it "exposes the parsed record" do
      expect(handler.record.registrar).to eq("Example Registrar")
      expect(handler.record.expires_on).to eq(Time.utc(2027, 1, 1))
    end
  end

  describe "an available domain" do
    subject(:handler) { handler_for("No match for EXAMPLE.COM") }

    it "is available" do
      expect(handler).to be_available
    end

    it "is not registered" do
      expect(handler).not_to be_registered
    end
  end

  describe "a lookup that produced no verdict" do
    subject(:handler) { handler_for("Query limit exceeded. Try again later.") }

    it "is not available" do
      # A permissive detector reports this as available, which for a registrar
      # means offering a registered domain for sale.
      expect(handler).not_to be_available
    end

    it "is not registered either" do
      expect(handler).not_to be_registered
    end

    it "says so explicitly" do
      expect(handler).to be_unknown
    end

    it "is still a valid lookup: the name and TLD were fine" do
      expect(handler).to be_valid
    end
  end

  describe "an unusable name" do
    subject(:handler) { handler_for("irrelevant", domain: "bad name!") }

    it "is invalid" do
      expect(handler).not_to be_valid
    end

    it "is not available" do
      expect(handler).not_to be_available
    end

    it "explains itself in the message" do
      expect(handler.whois_message).to include("not a valid domain")
    end
  end

  describe "#availability_details" do
    subject(:details) { handler_for("No match for EXAMPLE.COM").availability_details }

    it "names the rule that decided" do
      expect(details[:decided_by]).to be_a(String)
    end

    it "includes the whole trace" do
      expect(details[:trace]).to be_an(Array)
      expect(details[:trace].first).to include(:rule, :matched)
    end

    it "includes a bounded preview rather than the whole record" do
      expect(details[:response_preview].length).to be <= 203
    end
  end

  describe "camelCase aliases" do
    subject(:handler) { handler_for("No match for EXAMPLE.COM") }

    it "keeps the camelCase method names working" do
      expect(handler.isAvailable).to be(true)
      expect(handler.isValid).to be(true)
      expect(handler.isPremium).to be(false)
      expect(handler.getTld).to eq(".com")
      expect(handler.getSld).to eq("example")
      expect(handler.getWhoisMessage).to include("No match")
      expect(handler.getAvailabilityDetails).to be_a(Hash)
    end
  end

  describe ".whois" do
    it "builds a handler through .new" do
      # Stubbed rather than run: the real path would query a live registry.
      allow(described_class).to receive(:new).with("example.com").and_return(:handler)

      expect(described_class.whois("example.com")).to eq(:handler)
    end

    it "passes options through to the configuration" do
      allow(described_class).to receive(:new).with("example.com", prefer: :whois)
                                             .and_return(:handler)

      expect(described_class.whois("example.com", prefer: :whois)).to eq(:handler)
    end

    it "rejects an unknown option" do
      expect { described_class.whois("example.com", nonsense: 1) }
        .to raise_error(ArgumentError, /nonsense/)
    end
  end
end
