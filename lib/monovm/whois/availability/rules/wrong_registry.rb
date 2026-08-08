# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The server we reached does not serve this TLD.
        #
        # Two shapes of this exist. A WHOIS server may say so outright ("TLD not
        # supported"), or — more dangerously — a TLD may be mapped to an address
        # registry by mistake. RIPE, APNIC, ARIN and friends answer any domain query
        # with +%ERROR:101: no entries found+, which reads as "no entries found" to a
        # keyword scan and therefore as availability for every name under that TLD.
        #
        # Either way the response describes the server's capabilities, not the
        # domain, so the only honest verdict is +:unknown+.
        class WrongRegistry < Rule
          def call(context)
            return nil if context.empty?

            # As with {ServerRefusal}: an RDAP document reports this structurally, and
            # its Terms of Service prose is not evidence about the server's coverage.
            return nil unless context.json.nil?

            matched = context.find(Patterns::UNSUPPORTED)
            if matched
              return unknown(
                reason: "the server does not serve #{context.tld || "this TLD"}",
                evidence: matched
              )
            end

            banner = context.find(Patterns::WRONG_REGISTRY_BANNERS)
            return nil if banner.nil?

            unknown(
              reason: "reached an address registry, not the domain registry for " \
                      "#{context.tld || "this TLD"}",
              evidence: banner
            )
          end
        end
      end
    end
  end
end
