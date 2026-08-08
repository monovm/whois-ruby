# frozen_string_literal: true

RSpec.describe MonoVM::Whois::Referral::Follower do
  subject(:follower) { described_class.new(transport_factory: FakeTransportFactory.new(transport)) }

  let(:transport) { FakeTransport.new(default: "Registrant Name: Alice") }
  let(:parser) { MonoVM::Whois::Parser::Selector.default }

  def follow(body, query: "example.com")
    response = whois_response(body, query: query, uri: "socket://whois.verisign.test")
    follower.follow(response: response, record: parser.parse(response), query: query)
  end

  it "follows the registrar WHOIS server from the record" do
    referral = follow(<<~TEXT)
      Domain Name: EXAMPLE.COM
      Registry Domain ID: 1
      Registrar WHOIS Server: whois.registrar.test
      Registrar: Example Registrar
    TEXT

    expect(referral).not_to be_nil
    expect(referral.endpoint.host).to eq("whois.registrar.test")
    expect(transport.calls.first[:query]).to eq("example.com")
  end

  it "finds the referral in the raw text when the parser missed the key" do
    referral = follow("WHOIS Server: whois.registrar.test\nSomething: else")

    expect(referral&.endpoint&.host).to eq("whois.registrar.test")
  end

  it "does not follow a server that points at itself" do
    expect(follow("Registrar WHOIS Server: whois.verisign.test")).to be_nil
    expect(transport.call_count).to eq(0)
  end

  it "does not follow IANA, which never carries the fuller record" do
    expect(follow("Registrar WHOIS Server: whois.iana.org")).to be_nil
  end

  it "ignores a placeholder value" do
    expect(follow("Registrar WHOIS Server: not.applicable")).to be_nil
  end

  it "ignores a value that is not a host name" do
    expect(follow("Registrar WHOIS Server: localhost")).to be_nil
  end

  it "strips a scheme the registry should not have included" do
    referral = follow("Registrar WHOIS Server: rwhois://whois.registrar.test/")

    expect(referral&.endpoint&.host).to eq("whois.registrar.test")
  end

  it "returns nil when there is no referral at all" do
    expect(follow("Domain Name: example.com\nStatus: active")).to be_nil
  end

  it "returns nil rather than raising when the registrar's server is unreachable" do
    # The registry already answered the question that matters.
    failing = FakeTransport.new(default: MonoVM::Whois::ConnectionError)
    follower = described_class.new(transport_factory: FakeTransportFactory.new(failing))

    response = whois_response("Registrar WHOIS Server: whois.registrar.test",
                              uri: "socket://whois.verisign.test")

    expect(
      follower.follow(response: response, record: parser.parse(response), query: "example.com")
    ).to be_nil
  end

  it "does nothing when hops are disabled" do
    follower = described_class.new(
      transport_factory: FakeTransportFactory.new(transport), max_hops: 0
    )
    response = whois_response("Registrar WHOIS Server: whois.registrar.test")

    expect(
      follower.follow(response: response, record: parser.parse(response), query: "example.com")
    ).to be_nil
  end

  it "does not follow a referral found in an RDAP response" do
    response = rdap_response({ "objectClassName" => "domain", "ldhName" => "example.com" })

    expect(
      follower.follow(response: response, record: parser.parse(response), query: "example.com")
    ).to be_nil
  end
end
