# frozen_string_literal: true

# The invariant this library exists to hold: a response that does not answer the
# question must never be reported as an available domain.
#
# See spec/support/non_answers.rb for the corpus and why each entry is there.
RSpec.describe MonoVM::Whois::Availability::Analyzer do
  subject(:analyzer) { described_class.new }

  NonAnswers::RESPONSES.each do |label, body|
    it "does not report availability for #{label}" do
      verdict = analyzer.analyze(response: whois_response(body), tld: ".com")

      expect(verdict).not_to be_available,
                             "expected #{label} not to be :available, got #{verdict.status} " \
                             "from #{verdict.rule.inspect}"
    end
  end

  describe "an empty response" do
    it "is unknown rather than available" do
      verdict = analyzer.analyze(response: whois_response(""), tld: ".com")

      expect(verdict).to be_unknown
    end
  end

  describe "a response with no signal at all" do
    it "falls through to unknown, not to available" do
      verdict = analyzer.analyze(response: whois_response("something entirely unrelated"),
                                 tld: ".test")

      expect(verdict).to be_unknown
      expect(verdict.reason).to include("no rule recognised")
    end
  end

  describe "the absence of registration fields" do
    it "is not treated as availability on its own" do
      # This is the inference the PHP original makes and this port refuses to: a
      # response with fewer than two registration fields is not thereby a free
      # domain. Without an opt-in, the verdict must be unknown.
      verdict = analyzer.analyze(
        response: whois_response("Some registry notice with no fields whatsoever."),
        tld: ".com",
        definition: definition(available_when_empty: false)
      )

      expect(verdict).to be_unknown
    end

    it "is treated as availability only where a TLD opts in" do
      verdict = analyzer.analyze(
        response: whois_response("% NIC Monaco WHOIS server\n"),
        tld: ".mc",
        definition: definition(tld: ".mc", available_when_empty: true)
      )

      expect(verdict).to be_available
      expect(verdict.rule).to eq("recordless")
    end

    it "still refuses when the opted-in TLD returns an error notice" do
      verdict = analyzer.analyze(
        response: whois_response("Error code: 01044 - usage restrictions applied"),
        tld: ".mc",
        definition: definition(tld: ".mc", available_when_empty: true)
      )

      expect(verdict).not_to be_available
    end
  end

  describe "registry boilerplate that talks about rate limiting" do
    # Regression, found against the live .org registry. PIR attaches a Terms of Service
    # notice to every RDAP answer, and that notice explains that a client sending "too
    # many queries" will be throttled. Prose-scanning the document for refusal wording
    # matched the policy text and reported every unregistered .org name as :unknown.
    #
    # RDAP states refusal structurally — an HTTP 401/403/429, or an errorCode — so its
    # prose must never be read as a refusal.
    let(:pir_terms) do
      "Public Interest Registry provides this RDAP service for informational " \
        "purposes only. Users must not enable high volume, automated processes. " \
        "A client that sends too many queries will be rate limited."
    end

    it "still reports an unregistered name as available" do
      document = {
        "rdapConformance" => ["rdap_level_0"],
        "notices" => [{ "title" => "Terms of Service", "description" => [pir_terms] }],
        "errorCode" => 404,
        "title" => "Domain not found"
      }

      verdict = analyzer.analyze(
        response: rdap_response(document, status: 404), tld: ".org"
      )

      expect(verdict).to be_available
      expect(verdict.rule).to eq("rdap_object")
    end

    it "still reports a registered name as registered" do
      document = {
        "rdapConformance" => ["rdap_level_0"],
        "notices" => [{ "title" => "Terms of Service", "description" => [pir_terms] }],
        "objectClassName" => "domain",
        "ldhName" => "example.org",
        "handle" => "1",
        "status" => ["active"]
      }

      verdict = analyzer.analyze(response: rdap_response(document), tld: ".org")

      expect(verdict).to be_registered
    end

    it "still honours a genuine RDAP refusal, which is structural" do
      document = { "errorCode" => 429, "title" => "Too many requests" }

      verdict = analyzer.analyze(response: rdap_response(document, status: 429), tld: ".org")

      expect(verdict).to be_unknown
      expect(verdict.rule).to eq("rdap_object")
    end

    it "still detects a refusal in a plain-text body from an RDAP endpoint" do
      # Not every endpoint answers with JSON when it is throttling; a text body from an
      # HTTP endpoint is still prose-scanned.
      response = MonoVM::Whois::Response.new(
        body: "Rate limit exceeded, try again later",
        endpoint: rdap_endpoint,
        query: "example.org",
        status: 200
      )

      expect(analyzer.analyze(response: response, tld: ".org")).to be_unknown
    end
  end

  describe "rule ordering" do
    it "puts every registered-concluding rule before every available-concluding one" do
      # The guarantee that makes the permissive rules safe. If this ever inverts, a
      # loose availability pattern could beat a real record.
      names = MonoVM::Whois::Availability::RuleSet.default.names

      registered_rules = %w[explicit_unavailability registration_fields]
      available_rules = %w[registry_marker availability_keywords no_match tld_specific
                           status_field recordless]

      last_registered = registered_rules.map { |name| names.index(name) }.max
      first_available = available_rules.map { |name| names.index(name) }.min

      expect(last_registered).to be < first_available
    end

    it "checks for a refusal before anything else" do
      names = MonoVM::Whois::Availability::RuleSet.default.names

      expect(names.first).to eq("server_refusal")
      expect(names[1]).to eq("wrong_registry")
    end

    it "lets a refusal win over wording that would otherwise read as available" do
      # Both signals are present. The refusal must take precedence.
      body = "No match for EXAMPLE.COM\nQuery limit exceeded, try again later."

      verdict = analyzer.analyze(response: whois_response(body), tld: ".com")

      expect(verdict).to be_unknown
      expect(verdict.rule).to eq("server_refusal")
    end

    it "lets a real record win over wording that would otherwise read as available" do
      body = <<~TEXT
        Domain Name: example.com
        Registrar: Example Registrar
        Creation Date: 2010-01-01T00:00:00Z
        Name Server: ns1.example.com
        Notice: if the domain is not found, contact your registrar.
      TEXT

      verdict = analyzer.analyze(response: whois_response(body), tld: ".com")

      expect(verdict).to be_registered
    end
  end
end
