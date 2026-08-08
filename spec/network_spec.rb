# frozen_string_literal: true

# Live lookups against real registries.
#
# Excluded unless RUN_NETWORK_TESTS is set: they are slow, they depend on someone
# else's uptime, and every run spends rate-limit budget. Run them with
# +rake spec_network+ before a release.
#
# The assertions are deliberately loose. A registry can change its wording overnight,
# and a spec that pins exact text would fail for reasons that are not this library's
# fault. What is asserted is the part that must never drift: a domain everyone knows
# is registered must not come back available, and the transport must actually work.
RSpec.describe "live registry lookups", :network do
  before do
    WebMock.allow_net_connect!
    MonoVM::Whois.configure do |config|
      config.throttle_interval = 1.0
      config.socket_read_timeout = 20
      config.http_read_timeout = 20
    end
  end

  after { WebMock.disable_net_connect!(allow_localhost: true) }

  # A name nobody has registered, regenerated per run so a previous run cannot have
  # taken it and so it is never in anyone's cache.
  def unregistered_name(tld)
    "monovm-probe-#{Time.now.to_i}-#{rand(100_000)}#{tld}"
  end

  describe "registered domains" do
    { "google.com" => ".com", "bbc.co.uk" => ".co.uk", "denic.de" => ".de" }.each do |name, tld|
      it "reports #{name} as registered" do
        result = MonoVM::Whois.lookup(name)

        expect(result).not_to be_available,
                              "#{name} came back #{result.status} via #{result.verdict&.rule}: " \
                              "#{result.reason}"
        expect(result.tld).to eq(tld)
      end
    end

    it "returns a parsed record for google.com" do
      record = MonoVM::Whois.lookup("google.com").record

      expect(record).not_to be_nil
      expect(record.registrar).to be_a(String)
      expect(record.nameservers).not_to be_empty
      expect(record.created_on).to be_a(Time)
    end
  end

  describe "unregistered domains" do
    [".com", ".net", ".org"].each do |tld|
      it "reports a freshly invented #{tld} name as available" do
        result = MonoVM::Whois.lookup(unregistered_name(tld))

        expect(result).to be_available,
                          "expected available, got #{result.status} via " \
                          "#{result.verdict&.rule}: #{result.reason}"
      end
    end
  end

  describe "internationalised domains" do
    it "looks up an IDN through punycode" do
      result = MonoVM::Whois.lookup("münchen.de")

      expect(result).not_to be_available
    end
  end

  describe "RDAP" do
    it "prefers RDAP for .com and gets a structured answer" do
      MonoVM::Whois.configure { |config| config.prefer = :rdap }
      result = MonoVM::Whois.lookup("google.com")

      expect(result.response).to be_rdap
      expect(result.verdict.rule).to eq("rdap_object")
    end

    it "still works when forced onto port 43" do
      MonoVM::Whois.configure { |config| config.prefer = :whois }
      result = MonoVM::Whois.lookup("google.com")

      expect(result.response).to be_whois
      expect(result).not_to be_available
    end
  end

  describe "bulk checks" do
    it "checks several names across registries concurrently" do
      results = MonoVM::Whois.whois(%w[google.com bbc.co.uk denic.de])

      expect(results.values).to all(satisfy { |status| status != :available })
    end

    it "expands a bare name across popular TLDs" do
      results = MonoVM::Whois.whois("google")

      expect(results.keys).to include("google.com", "google.net")
    end
  end
end
