# frozen_string_literal: true

# Responses where the server did not answer the question asked.
#
# Each of these is classified "available" by the PHP implementation, because its
# detector treats the absence of registration data as evidence of availability. For a
# registrar that means offering a registered domain for sale, so the suite asserts
# against every one of them.
module NonAnswers
  RESPONSES = {
    "a .pl rate-limit notice" => <<~TEXT,
      %% Registry limit exceeded. Try again later.
    TEXT

    "a .cz query-rate refusal" => <<~TEXT,
      Your connection limit exceeded. Please slow down and try again later.
    TEXT

    "an .it excessive-querying block" => <<~TEXT,
      Access to this WHOIS server is denied: excessive querying detected.
    TEXT

    "a .li blocked client" => <<~TEXT,
      Requests of this client are not permitted. Please use https://www.nic.li
    TEXT

    "a .shop retired port 43" => <<~TEXT,
      The WHOIS service has been retired. Queries are now served via RDAP at
      https://rdap.example/
    TEXT

    "a busy server" => <<~TEXT,
      The server is busy, please try again later.
    TEXT

    "a rate-limited registry" => <<~TEXT,
      Maximum query rate exceeded for your network. Please try again later.
    TEXT

    "a RIPE database banner" => <<~TEXT,
      % This is the RIPE Database query service.
      % The objects are in RPSL format.
      %ERROR:101: no entries found
    TEXT

    "an ARIN banner" => <<~TEXT,
      # American Registry for Internet Numbers
      # whois.arin.net
      No match found for example.test
    TEXT

    "an APNIC banner" => <<~TEXT,
      [whois.apnic.net]
      %ERROR:101: no entries found
    TEXT

    "an explicit unsupported TLD" => <<~TEXT,
      This TLD is not supported by this WHOIS server.
    TEXT

    "a server with no WHOIS service for the TLD" => <<~TEXT,
      No whois server is known for this kind of object.
    TEXT

    "an HTML 403 page" => <<~TEXT,
      <html><head><title>403 Forbidden</title></head>
      <body>Access denied. Your request could not be processed.</body></html>
    TEXT

    "a legal preamble with no record" => <<~TEXT,
      % By submitting a query you agree to the terms of use.
      % The data in this WHOIS database is provided for information purposes.
      % Copyright the registry. All rights reserved.
      % Personal data is redacted for privacy under GDPR.
    TEXT

    "a bare registry banner" => <<~TEXT
      % Registry WHOIS service
      % For more information on WHOIS status codes, please visit the registry site.
    TEXT
  }.freeze
end
