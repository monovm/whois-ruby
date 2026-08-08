# frozen_string_literal: true

# Builders for the value objects specs need constantly.
module ResponseBuilder
  WHOIS_ENDPOINT = "socket://whois.example.test"
  RDAP_ENDPOINT = "https://rdap.example.test/domain/"

  def endpoint(uri = WHOIS_ENDPOINT)
    MonoVM::Whois::Endpoint.parse(uri)
  end

  def rdap_endpoint(uri = RDAP_ENDPOINT)
    MonoVM::Whois::Endpoint.parse(uri)
  end

  # A port 43 response.
  def whois_response(body, query: "example.com", uri: WHOIS_ENDPOINT)
    MonoVM::Whois::Response.new(body: body, endpoint: endpoint(uri), query: query)
  end

  # An RDAP response. Pass a Hash and it is serialised for you.
  def rdap_response(body, query: "example.com", status: 200, uri: RDAP_ENDPOINT)
    body = JSON.generate(body) if body.is_a?(Hash)

    MonoVM::Whois::Response.new(
      body: body,
      endpoint: rdap_endpoint(uri),
      query: query,
      status: status
    )
  end

  def definition(tld: ".com", **attributes)
    MonoVM::Whois::Registry::Definition.new(
      tld: tld,
      whois_endpoint: endpoint,
      **attributes
    )
  end

  # An analysis context for the rules. Deliberately not named +context+: that is
  # RSpec's own example-group keyword, and shadowing it reads terribly.
  def analysis(body = nil, tld: ".com", definition: nil, response: nil)
    MonoVM::Whois::Availability::Context.new(
      response: response || whois_response(body.to_s),
      tld: tld,
      definition: definition
    )
  end
end
