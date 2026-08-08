# frozen_string_literal: true

RSpec.describe MonoVM::Whois::DomainName do
  describe ".parse" do
    it "strips everything around the host name" do
      name = described_class.parse("  HTTPS://user:pass@WWW.Example.COM:8080/path?q=1#frag  ")

      expect(name.to_s).to eq("www.example.com")
    end

    it "drops a trailing root dot" do
      expect(described_class.parse("example.com.").to_s).to eq("example.com")
    end

    it "drops leading dots" do
      expect(described_class.parse(".example.com").to_s).to eq("example.com")
    end

    it "downcases" do
      expect(described_class.parse("EXAMPLE.COM").to_s).to eq("example.com")
    end

    it "keeps a bare name without a TLD" do
      name = described_class.parse("monovm")

      expect(name.to_s).to eq("monovm")
      expect(name).to be_bare
      expect(name).to be_valid
    end

    it "rejects a non-String" do
      expect { described_class.parse(42) }.to raise_error(MonoVM::Whois::InvalidDomainError)
    end

    it "returns an invalid name rather than raising, so a batch survives one bad entry" do
      name = described_class.parse("not a domain!")

      expect(name).not_to be_valid
    end
  end

  describe ".parse!" do
    it "raises for an unusable name" do
      expect { described_class.parse!("!!") }.to raise_error(MonoVM::Whois::InvalidDomainError)
    end

    it "returns the name when it is usable" do
      expect(described_class.parse!("example.com").to_s).to eq("example.com")
    end
  end

  describe "#ascii" do
    it "converts internationalised labels to punycode" do
      expect(described_class.parse("münchen.de").ascii).to eq("xn--mnchen-3ya.de")
    end

    it "converts every non-ASCII label" do
      expect(described_class.parse("münchen.中国").ascii).to eq("xn--mnchen-3ya.xn--fiqs8s")
    end

    it "leaves an ASCII name untouched" do
      expect(described_class.parse("example.com").ascii).to eq("example.com")
    end

    it "normalises a decomposed form so it punycodes identically" do
      # "u" + COMBINING DIAERESIS must reach the wire as the same label as "ü".
      composed = described_class.parse("münchen.de")
      decomposed = described_class.parse("münchen.de")

      expect(decomposed.ascii).to eq(composed.ascii)
      expect(decomposed.ascii).to eq("xn--mnchen-3ya.de")
    end
  end

  describe "#idn?" do
    it "is true when punycoding changed the name" do
      expect(described_class.parse("münchen.de")).to be_idn
    end

    it "is false for an ASCII name" do
      expect(described_class.parse("example.com")).not_to be_idn
    end
  end

  describe "#valid?" do
    it "accepts a normal name" do
      expect(described_class.parse("example.co.uk")).to be_valid
    end

    it "accepts a punycoded label" do
      expect(described_class.parse("xn--mnchen-3ya.de")).to be_valid
    end

    it "rejects a label starting with a hyphen" do
      expect(described_class.parse("-bad.com")).not_to be_valid
    end

    it "rejects a label ending with a hyphen" do
      expect(described_class.parse("bad-.com")).not_to be_valid
    end

    it "rejects an empty label from a doubled dot" do
      expect(described_class.parse("bad..com")).not_to be_valid
    end

    it "rejects a label over 63 characters" do
      expect(described_class.parse("#{"a" * 64}.com")).not_to be_valid
    end

    it "accepts a label of exactly 63 characters" do
      expect(described_class.parse("#{"a" * 63}.com")).to be_valid
    end

    it "rejects a name over 253 characters" do
      long = (["a" * 60] * 5).join(".")

      expect(described_class.parse("#{long}.com")).not_to be_valid
    end

    it "rejects an empty string" do
      expect(described_class.parse("")).not_to be_valid
    end

    it "rejects underscores, which are not legal in a host name" do
      expect(described_class.parse("bad_name.com")).not_to be_valid
    end
  end

  describe "#join" do
    it "appends a TLD to a bare name" do
      expect(described_class.parse("monovm").join(".com").to_s).to eq("monovm.com")
    end

    it "accepts a TLD without a leading dot" do
      expect(described_class.parse("monovm").join("com").to_s).to eq("monovm.com")
    end
  end

  describe "equality" do
    it "compares on the normalised form, so duplicates collapse" do
      a = described_class.parse("HTTPS://Example.com/")
      b = described_class.parse("example.com")

      expect(a).to eq(b)
      expect([a, b].uniq.length).to eq(1)
    end

    it "hashes equal names together" do
      expect(described_class.parse("a.com").hash).to eq(described_class.parse("A.com").hash)
    end
  end

  describe "#labels" do
    it "splits on dots" do
      expect(described_class.parse("www.example.co.uk").labels).to eq(%w[www example co uk])
    end
  end

  it "is frozen, so a name cannot be mutated after construction" do
    expect(described_class.parse("example.com")).to be_frozen
  end
end
