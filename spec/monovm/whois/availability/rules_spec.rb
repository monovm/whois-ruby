# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Availability::Rules do
  # Each rule is exercised on its own, so a failure names the rule rather than
  # pointing vaguely at "detection".

  describe MonoVM::Whois::Availability::Rules::ServerRefusal do
    subject(:rule) { described_class.new }

    it "recognises a rate limit" do
      verdict = rule.call(analysis("Query rate exceeded. Try again later."))

      expect(verdict).to be_unknown
      expect(verdict.rule).to eq("server_refusal")
      expect(verdict.evidence).to be_a(String)
    end

    it "recognises a retired port 43 endpoint" do
      expect(rule.call(analysis("The WHOIS service has been retired."))).to be_unknown
    end

    it "passes on a normal record" do
      expect(rule.call(analysis("Domain Name: example.com"))).to be_nil
    end

    it "passes on an empty response, leaving it to the fallthrough" do
      expect(rule.call(analysis(""))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::WrongRegistry do
    subject(:rule) { described_class.new }

    it "recognises an explicit unsupported TLD" do
      expect(rule.call(analysis("TLD is not supported"))).to be_unknown
    end

    it "recognises an address registry banner" do
      body = "% This is the RIPE Database query service.\n%ERROR:101: no entries found"
      verdict = rule.call(analysis(body, tld: ".ke"))

      expect(verdict).to be_unknown
      expect(verdict.reason).to include("address registry")
    end

    it "passes on a domain registry's answer" do
      expect(rule.call(analysis("Domain Name: example.com"))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::RdapObject do
    subject(:rule) { described_class.new }

    it "reads a domain object as registered" do
      response = rdap_response({
                                 "objectClassName" => "domain",
                                 "ldhName" => "example.com",
                                 "handle" => "2336799_DOMAIN_COM-VRSN",
                                 "status" => ["client transfer prohibited"]
                               })

      verdict = rule.call(analysis(nil, response: response))

      expect(verdict).to be_registered
      expect(verdict.evidence).to eq("example.com")
    end

    it "reads errorCode 404 as available" do
      response = rdap_response({ "errorCode" => 404, "title" => "Domain not found" }, status: 404)

      expect(rule.call(analysis(nil, response: response))).to be_available
    end

    it "reads a bodyless HTTP 404 as available" do
      response = rdap_response("", status: 404)

      expect(rule.call(analysis(nil, response: response))).to be_available
    end

    it "reads any other errorCode as unknown, not available" do
      response = rdap_response({ "errorCode" => 429, "title" => "Too many requests" }, status: 429)

      verdict = rule.call(analysis(nil, response: response))

      expect(verdict).to be_unknown
      expect(verdict.reason).to include("429")
    end

    it "does not treat a help document as a registration" do
      response = rdap_response({ "objectClassName" => "help" })

      expect(rule.call(analysis(nil, response: response))).to be_nil
    end

    it "passes on a port 43 response" do
      expect(rule.call(analysis("Domain Name: example.com"))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::PremiumName do
    subject(:rule) { described_class.new }

    it "reports a premium name when the registry marker appears" do
      verdict = rule.call(
        analysis("This name is a Premium Reserved name.",
                 definition: definition(premium_match: "Premium Reserved"))
      )

      expect(verdict).to be_premium
    end

    it "passes when the TLD has no premium marker configured" do
      expect(rule.call(analysis("Premium Reserved", definition: definition))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::ExplicitUnavailability do
    subject(:rule) { described_class.new }

    it "recognises a status of registered" do
      expect(rule.call(analysis("Status: registered"))).to be_registered
    end

    it "recognises a dot-padded status key" do
      # Traficom (.fi) aligns values with dots. A plain "status:" match misses this,
      # and a missed "Registered" would be read as availability.
      expect(rule.call(analysis("status.............: Registered", tld: ".fi"))).to be_registered
    end

    it "recognises DENIC's Status: connect" do
      expect(rule.call(analysis("Status: connect", tld: ".de"))).to be_registered
    end

    it "recognises DENIC's Status: invalid as not available" do
      # The name cannot be registered as spelled. It must never read as free.
      expect(rule.call(analysis("Status: invalid", tld: ".de"))).to be_registered
    end

    it "recognises a registry restriction notice" do
      body = "Error code: 01044 - this domain has usage restrictions applied"

      expect(rule.call(analysis(body, tld: ".sx"))).to be_registered
    end

    it "recognises an EPP redemption status" do
      expect(rule.call(analysis("Domain Status: redemptionPeriod"))).to be_registered
    end

    it "ignores conditional prose in a comment line" do
      body = "% If the domain is registered, contact the registrar.\nNo match for EXAMPLE.COM"

      expect(rule.call(analysis(body))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::RegistrationFields do
    subject(:rule) { described_class.new }

    it "reports registered once three record fields are present" do
      body = <<~TEXT
        Domain Name: example.com
        Registrar: Example Registrar
        Creation Date: 2010-01-01T00:00:00Z
      TEXT

      expect(rule.call(analysis(body))).to be_registered
    end

    it "passes with only two fields, which a chatty notice can reach" do
      expect(rule.call(analysis("Domain Name: example.com\nRegistrar: none"))).to be_nil
    end

    it "counts dot-padded field names" do
      body = <<~TEXT
        domain.............: example.fi
        registrar..........: Example Oy
        created............: 2010-01-01
      TEXT

      expect(rule.call(analysis(body, tld: ".fi"))).to be_registered
    end
  end

  describe MonoVM::Whois::Availability::Rules::RegistryMarker do
    subject(:rule) { described_class.new }

    it "reports available when the configured marker appears" do
      verdict = rule.call(
        analysis("No match for EXAMPLE.COM", definition: definition(available_match: "No match for"))
      )

      expect(verdict).to be_available
    end

    it "ignores a marker that only appears in a comment line" do
      body = "% No match for is what we say when a domain is free.\nDomain Name: example.com"

      expect(rule.call(analysis(body, definition: definition(available_match: "No match for")))).to be_nil
    end

    it "passes when the TLD has no marker configured" do
      expect(rule.call(analysis("No match for EXAMPLE.COM", definition: definition))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::AvailabilityKeywords do
    subject(:rule) { described_class.new }

    ["No match", "NOT FOUND", "No entries found", "Domain not found",
     "no se encontro el objeto", "Object does not exist"].each do |phrase|
      it "recognises #{phrase.inspect}" do
        expect(rule.call(analysis(phrase))).to be_available
      end
    end

    it "ignores the phrase when it appears only in registry boilerplate" do
      body = "% By submitting a query you agree that no match will be logged."

      expect(rule.call(analysis(body))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::NoMatch do
    subject(:rule) { described_class.new }

    it "tolerates irregular whitespace a substring scan would miss" do
      expect(rule.call(analysis("No\t\tmatch  for EXAMPLE.COM"))).to be_available
    end
  end

  describe MonoVM::Whois::Availability::Rules::TldSpecific do
    subject(:rule) { described_class.new }

    it "applies a pattern scoped to the TLD" do
      expect(rule.call(analysis("we do not have an entry in our database", tld: ".ch")))
        .to be_available
    end

    it "passes when the TLD has no table entry" do
      expect(rule.call(analysis("available", tld: ".nowhere"))).to be_nil
    end

    it "passes when no TLD is known" do
      expect(rule.call(analysis("available", tld: nil))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::StatusField do
    subject(:rule) { described_class.new }

    it "reads an explicit available status" do
      expect(rule.call(analysis("Status: AVAILABLE"))).to be_available
    end

    it "refuses when the response is an error notice" do
      body = "Error code: 500\nStatus: available"

      expect(rule.call(analysis(body))).to be_nil
    end
  end

  describe MonoVM::Whois::Availability::Rules::Recordless do
    subject(:rule) { described_class.new }

    it "stays silent unless the TLD opts in" do
      expect(rule.call(analysis("% banner only", definition: definition))).to be_nil
    end

    it "reports available for an opted-in TLD with no record" do
      verdict = rule.call(
        analysis("% NIC banner", tld: ".mc",
                                 definition: definition(tld: ".mc", available_when_empty: true))
      )

      expect(verdict).to be_available
    end

    it "refuses when the response holds a record after all" do
      body = <<~TEXT
        registrar: Example
        created: 2010-01-01
      TEXT

      verdict = rule.call(
        analysis(body, tld: ".mc", definition: definition(tld: ".mc", available_when_empty: true))
      )

      expect(verdict).to be_nil
    end
  end
end
