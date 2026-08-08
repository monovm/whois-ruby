# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The response states that the name exists.
        #
        # Per-TLD wording is consulted first, because some registries use words that
        # would be ambiguous elsewhere: DENIC's +Status: invalid+ means the name
        # cannot be registered as spelled, and Nominet answers a registered +.uk+
        # name with nothing more definitive than "Registered".
        #
        # Matching happens against the response with commentary stripped. Registries
        # put conditional prose in their preamble ("if the domain is registered,
        # contact the registrar"), and matching that would mark a free name as taken.
        class ExplicitUnavailability < Rule
          def call(context)
            return nil if context.empty?

            tld_patterns = Patterns::TLD_UNAVAILABILITY[context.tld]
            if tld_patterns
              matched = context.find(tld_patterns, source: :significant)
              if matched
                return registered(
                  reason: "#{context.tld} registries report a registration this way",
                  evidence: matched
                )
              end
            end

            matched = context.find(Patterns::UNAVAILABILITY, source: :significant)
            return nil if matched.nil?

            registered(reason: "the response states the name is registered", evidence: matched)
          end
        end
      end
    end
  end
end
