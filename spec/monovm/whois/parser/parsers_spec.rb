# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Parser do
  describe MonoVM::Whois::Parser::IcannRdd do
    subject(:parser) { described_class.new }

    let(:body) do
      <<~TEXT
        Domain Name: EXAMPLE.COM
        Registry Domain ID: 2336799_DOMAIN_COM-VRSN
        Registrar WHOIS Server: whois.registrar.test
        Registrar URL: http://www.registrar.test
        Updated Date: 2026-01-16T18:26:50Z
        Creation Date: 1995-08-14T04:00:00Z
        Registry Expiry Date: 2027-08-13T04:00:00Z
        Registrar: Example Registrar, LLC
        Registrar IANA ID: 376
        Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
        Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
        Name Server: NS1.EXAMPLE.COM
        Name Server: NS2.EXAMPLE.COM
        DNSSEC: signedDelegation
        Registrant Organization: REDACTED FOR PRIVACY
        >>> Last update of WHOIS database: 2026-08-05T12:00:00Z <<<
      TEXT
    end

    let(:record) { parser.parse(whois_response(body)) }

    it "claims a gTLD record" do
      expect(parser.applicable?(whois_response(body))).to be(true)
    end

    it "extracts the domain and registrar" do
      expect(record.domain).to eq("EXAMPLE.COM")
      expect(record.registrar).to eq("Example Registrar, LLC")
      expect(record.registrar_iana_id).to eq("376")
    end

    it "lowercases the referral server so it can be compared" do
      expect(record.registrar_whois_server).to eq("whois.registrar.test")
    end

    it "parses the dates" do
      expect(record.created_on).to eq(Time.utc(1995, 8, 14, 4, 0, 0))
      expect(record.expires_on).to eq(Time.utc(2027, 8, 13, 4, 0, 0))
      expect(record.updated_on).to eq(Time.utc(2026, 1, 16, 18, 26, 50))
    end

    it "does not mistake the database trailer for the domain's updated date" do
      # ">>> Last update of WHOIS database" is about the registry's database, not the
      # registration, and it sorts later than the real Updated Date.
      expect(record.updated_on).not_to eq(Time.utc(2026, 8, 5, 12, 0, 0))
    end

    it "collects every nameserver, lowercased" do
      expect(record.nameservers).to eq(%w[ns1.example.com ns2.example.com])
    end

    it "collects every status and strips the EPP documentation URL" do
      expect(record.statuses).to eq(%w[clientDeleteProhibited clientTransferProhibited])
    end

    it "treats a GDPR redaction as absent rather than as a registrant name" do
      expect(record.registrant).to be_nil
    end

    it "reports the transfer lock" do
      expect(record).to be_transfer_prohibited
    end

    it "reports DNSSEC" do
      expect(record).to be_dnssec
    end

    it "keeps every raw field reachable" do
      expect(record["Registry Domain ID"]).to eq("2336799_DOMAIN_COM-VRSN")
    end

    it "prefers the registry expiry date over the registrar's copy" do
      with_both = "#{body}Registrar Registration Expiration Date: 2030-01-01T00:00:00Z\n"
      parsed = parser.parse(whois_response(with_both))

      expect(parsed.expires_on).to eq(Time.utc(2027, 8, 13, 4, 0, 0))
    end

    it "computes days until expiry" do
      days = record.days_until_expiry(now: Time.utc(2027, 8, 3, 4, 0, 0))

      expect(days).to eq(10)
    end
  end

  describe MonoVM::Whois::Parser::KeyValue do
    subject(:parser) { described_class.new }

    it "reads dot-padded keys, as Traficom emits for .fi" do
      body = <<~TEXT
        domain.............: example.fi
        status.............: Registered
        created............: 12.5.2015
        expires............: 12.5.2027
        nserver............: ns1.example.fi [OK]
      TEXT

      record = parser.parse(whois_response(body))

      expect(record.domain).to eq("example.fi")
      expect(record.created_on).to eq(Time.local(2015, 5, 12))
      expect(record.nameservers).to eq(["ns1.example.fi"])
    end

    it "strips an IP address that shares the nameserver line" do
      record = parser.parse(whois_response("nserver: ns1.example.de 192.0.2.1"))

      expect(record.nameservers).to eq(["ns1.example.de"])
    end

    it "reads a value containing a colon" do
      record = parser.parse(whois_response("Registrar URL: https://example.test/whois"))

      expect(record.registrar_url).to eq("https://example.test/whois")
    end

    it "ignores comment lines" do
      body = "% Domain Name: not-a-real-record.com\nDomain Name: real.com"

      expect(parser.parse(whois_response(body)).domain).to eq("real.com")
    end

    it "collects contact blocks by role" do
      body = <<~TEXT
        Registrant Name: Alice Example
        Registrant Email: alice@example.test
        Admin Name: Bob Example
        Tech Email: tech@example.test
      TEXT

      record = parser.parse(whois_response(body))

      expect(record.contacts[:registrant]).to include(name: "Alice Example",
                                                      email: "alice@example.test")
      expect(record.contacts[:admin]).to include(name: "Bob Example")
      expect(record.contacts[:tech]).to include(email: "tech@example.test")
    end

    it "reads a day-first date the way registries write it" do
      record = parser.parse(whois_response("created: 13/08/2026"))

      expect(record.created_on.month).to eq(8)
      expect(record.created_on.day).to eq(13)
    end

    it "returns an empty record for a not-found response" do
      expect(parser.parse(whois_response("No match for EXAMPLE.COM"))).to be_empty
    end
  end

  describe MonoVM::Whois::Parser::RdapJson do
    subject(:parser) { described_class.new }

    let(:document) do
      {
        "objectClassName" => "domain",
        "handle" => "2336799_DOMAIN_COM-VRSN",
        "ldhName" => "EXAMPLE.COM",
        "status" => ["client transfer prohibited"],
        "events" => [
          { "eventAction" => "registration", "eventDate" => "1995-08-14T04:00:00Z" },
          { "eventAction" => "expiration", "eventDate" => "2027-08-13T04:00:00Z" },
          { "eventAction" => "last changed", "eventDate" => "2026-01-16T18:26:50Z" },
          { "eventAction" => "last update of RDAP database", "eventDate" => "2026-08-05T00:00:00Z" }
        ],
        "nameservers" => [
          { "objectClassName" => "nameserver", "ldhName" => "NS1.EXAMPLE.COM" },
          { "objectClassName" => "nameserver", "ldhName" => "NS2.EXAMPLE.COM" }
        ],
        "secureDNS" => { "delegationSigned" => true },
        "entities" => [
          {
            "objectClassName" => "entity",
            "handle" => "376",
            "roles" => ["registrar"],
            "publicIds" => [{ "type" => "IANA Registrar ID", "identifier" => "376" }],
            "vcardArray" => [
              "vcard",
              [
                %w[version {} text 4.0],
                ["fn", {}, "text", "Example Registrar, LLC"],
                ["org", {}, "text", "Example Registrar, LLC"]
              ]
            ]
          },
          {
            "objectClassName" => "entity",
            "roles" => ["registrant"],
            "vcardArray" => [
              "vcard",
              [
                ["fn", {}, "text", "Alice Example"],
                ["email", {}, "text", "alice@example.test"],
                ["adr", {}, "text", ["", "", "1 Road", "Town", "", "12345", "GB"]]
              ]
            ]
          }
        ]
      }
    end

    let(:record) { parser.parse(rdap_response(document)) }

    it "claims an RDAP document" do
      expect(parser.applicable?(rdap_response(document))).to be(true)
    end

    it "does not claim a port 43 response" do
      expect(parser.applicable?(whois_response("Domain Name: example.com"))).to be(false)
    end

    it "reads the name and handle" do
      expect(record.domain).to eq("EXAMPLE.COM")
      expect(record.registry_id).to eq("2336799_DOMAIN_COM-VRSN")
    end

    it "maps events onto dates" do
      expect(record.created_on).to eq(Time.utc(1995, 8, 14, 4, 0, 0))
      expect(record.expires_on).to eq(Time.utc(2027, 8, 13, 4, 0, 0))
      expect(record.updated_on).to eq(Time.utc(2026, 1, 16, 18, 26, 50))
    end

    it "ignores the RDAP database's own timestamp" do
      expect(record.updated_on).not_to eq(Time.utc(2026, 8, 5))
    end

    it "reads nameservers" do
      expect(record.nameservers).to eq(%w[ns1.example.com ns2.example.com])
    end

    it "reads the registrar out of the entity list" do
      expect(record.registrar).to eq("Example Registrar, LLC")
      expect(record.registrar_iana_id).to eq("376")
    end

    it "walks the jCard for the registrant" do
      expect(record.registrant).to eq("Alice Example")
      expect(record.contacts[:registrant]).to include(
        email: "alice@example.test",
        country: "GB"
      )
    end

    it "translates secureDNS into the same vocabulary the WHOIS parsers use" do
      expect(record.dnssec).to eq("signedDelegation")
      expect(record).to be_dnssec
    end

    it "reports an unsigned delegation" do
      unsigned = document.merge("secureDNS" => { "delegationSigned" => false })

      expect(parser.parse(rdap_response(unsigned))).not_to be_dnssec
    end
  end

  describe MonoVM::Whois::Parser::Selector do
    subject(:selector) { described_class.default }

    it "picks the RDAP parser for JSON" do
      response = rdap_response({ "objectClassName" => "domain", "ldhName" => "a.com" })

      expect(selector.parser_for(response)).to be_a(MonoVM::Whois::Parser::RdapJson)
    end

    it "picks the ICANN parser for a gTLD record" do
      body = "Domain Name: a.com\nRegistry Domain ID: 1\nRegistrar WHOIS Server: whois.test\n"

      expect(selector.parser_for(whois_response(body))).to be_a(MonoVM::Whois::Parser::IcannRdd)
    end

    it "falls back to the key/value parser" do
      expect(selector.parser_for(whois_response("domain: a.test\n")))
        .to be_a(MonoVM::Whois::Parser::KeyValue)
    end

    it "returns an empty record when nothing applies" do
      expect(selector.parse(whois_response("   "))).to be_empty
    end

    it "survives a parser that raises, rather than failing the lookup" do
      exploding = Class.new(MonoVM::Whois::Parser::Base) do
        def applicable?(_response)
          true
        end

        def parse(_response)
          raise "boom"
        end
      end

      selector = described_class.new([exploding.new])
      record = selector.parse(whois_response("anything"))

      expect(record.fields["parse_error"]).to include("boom")
    end
  end
end
