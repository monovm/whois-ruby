# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The server answered, but declined to say anything about the domain.
        #
        # First in the chain, and that position is the point. Rate-limit notices,
        # "your client is blocked" messages and "port 43 is retired, use RDAP"
        # banners contain none of the wording that means "registered", so every
        # later rule passes on them and the response eventually reaches whichever
        # heuristic is loosest. In a permissive detector that heuristic answers
        # "available", which means a rate-limited registry reports its entire zone
        # as free to register.
        #
        # Deciding this first, and deciding it +:unknown+, is what makes the rest of
        # the chain safe to be permissive.
        class ServerRefusal < Rule
          def call(context)
            return nil if context.empty?

            # An RDAP document says "I refuse" structurally — an HTTP 401/403/429,
            # which the transport turns into an error, or an +errorCode+, which
            # {RdapObject} reads. Its prose must not be scanned for refusal wording,
            # because registries embed rate-limit *policy* in the Terms of Service
            # notice attached to every answer: PIR's .org responses explain that a
            # client sending "too many queries" will be throttled, and matching that
            # reported every unregistered .org name as unknown.
            return nil unless context.json.nil?

            matched = context.find(Patterns::REFUSAL)
            return nil if matched.nil?

            unknown(
              reason: "the server refused to answer the query",
              evidence: matched
            )
          end
        end
      end
    end
  end
end
