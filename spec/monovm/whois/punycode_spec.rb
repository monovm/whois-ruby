# frozen_string_literal: true

# Test data lives in a module rather than in the example group, so the constants do
# not leak into Object and RuboCop has nothing to complain about.
module PunycodeVectors
  # RFC 3492 section 7.1. Given as code points so the expectations do not depend on
  # this file's own encoding surviving a round trip through an editor.
  RFC = {
    "Arabic (Egyptian)" => {
      code_points: [0x0644, 0x064A, 0x0647, 0x0645, 0x0627, 0x0628, 0x062A, 0x0643,
                    0x0644, 0x0645, 0x0648, 0x0634, 0x0639, 0x0631, 0x0628, 0x064A, 0x061F],
      punycode: "egbpdaj6bu4bxfgehfvwxn"
    },
    "Chinese (simplified)" => {
      code_points: [0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587],
      punycode: "ihqwcrb4cv8a8dqg056pqjye"
    },
    "Chinese (traditional)" => {
      code_points: [0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587],
      punycode: "ihqwctvzc91f659drss3x8bo0yb"
    },
    "Russian (Cyrillic)" => {
      code_points: [0x043F, 0x043E, 0x0447, 0x0435, 0x043C, 0x0443, 0x0436, 0x0435,
                    0x043E, 0x043D, 0x0438, 0x043D, 0x0435, 0x0433, 0x043E, 0x0432,
                    0x043E, 0x0440, 0x044F, 0x0442, 0x043F, 0x043E, 0x0440, 0x0443,
                    0x0441, 0x0441, 0x043A, 0x0438],
      punycode: "b1abfaaepdrnnbgefbadotcwatmq2g4l"
    }
  }.freeze

  # ACE forms of the internationalised ccTLDs. IANA publishes these and they cannot
  # drift, which makes them the strongest fixtures available.
  TLDS = {
    "中国" => "fiqs8s",
    "рф" => "p1ai",
    "台灣" => "kpry57d",
    "한국" => "3e0b707e",
    "ελ" => "qxam",
    "укр" => "j1amh"
  }.freeze

  ROUND_TRIP = %w[
    münchen bücher españa 中国 рф 日本語 한국어
    ελληνικά עברית العربية français português türkçe
    ñoño åäö žluťoučký ไทย a ü ascii
  ].freeze
end

RSpec.describe MonoVM::Whois::Punycode do
  describe ".encode" do
    PunycodeVectors::RFC.each do |label, vector|
      it "matches the RFC 3492 vector for #{label}" do
        input = vector[:code_points].pack("U*")

        expect(described_class.encode(input)).to eq(vector[:punycode])
      end
    end

    PunycodeVectors::TLDS.each do |unicode, ace|
      it "encodes #{unicode} to the published ACE form #{ace}" do
        expect(described_class.encode(unicode)).to eq(ace)
      end
    end

    it "keeps the basic prefix before the delimiter" do
      expect(described_class.encode("münchen")).to eq("mnchen-3ya")
      expect(described_class.encode("bücher")).to eq("bcher-kva")
      expect(described_class.encode("españa")).to eq("espaa-rta")
    end

    it "emits a trailing delimiter when every code point is basic" do
      # RFC 3492 step 2: the delimiter follows the literal portion whenever there is
      # one. Real IDNA never punycodes an all-ASCII label, but the primitive must
      # still round trip.
      expect(described_class.encode("ascii")).to eq("ascii-")
    end

    it "encodes an empty label as an empty string" do
      expect(described_class.encode("")).to eq("")
    end
  end

  describe ".decode" do
    PunycodeVectors::RFC.each do |label, vector|
      it "reverses the RFC 3492 vector for #{label}" do
        expected = vector[:code_points].pack("U*")

        expect(described_class.decode(vector[:punycode])).to eq(expected)
      end
    end

    PunycodeVectors::TLDS.each do |unicode, ace|
      it "decodes #{ace} back to #{unicode}" do
        expect(described_class.decode(ace)).to eq(unicode)
      end
    end

    it "rejects a character outside the punycode alphabet" do
      expect { described_class.decode("mnchen-3y!") }
        .to raise_error(MonoVM::Whois::Punycode::Error, /not a punycode digit/)
    end

    it "rejects a variable-length integer that never terminates" do
      expect { described_class.decode("abc-99999999") }
        .to raise_error(MonoVM::Whois::Punycode::Error)
    end

    it "rejects a non-basic code point before the delimiter" do
      expect { described_class.decode("münchen-abc") }
        .to raise_error(MonoVM::Whois::Punycode::Error, /before the delimiter/)
    end

    it "raises an error callers can catch as the library's base error" do
      expect(described_class::Error.ancestors).to include(MonoVM::Whois::Error)
    end
  end

  describe "round trips" do
    PunycodeVectors::ROUND_TRIP.each do |sample|
      it "survives encode then decode for #{sample}" do
        expect(described_class.decode(described_class.encode(sample))).to eq(sample)
      end
    end
  end
end
