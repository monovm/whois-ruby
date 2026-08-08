# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The regexp form of the not-found phrases.
        #
        # Overlaps {AvailabilityKeywords} on purpose. That rule does a fast substring
        # scan, which misses a registry that writes +No  match+ with two spaces or
        # +not\tfound+ with a tab; these patterns are whitespace-tolerant and catch
        # the rest. Cheap check first, thorough check second.
        class NoMatch < Rule
          def call(context)
            return nil if context.empty?

            matched = context.find(Patterns::NO_MATCH, source: :significant)
            return nil if matched.nil?

            available(
              reason: "the response matched a not-found pattern",
              evidence: matched
            )
          end
        end
      end
    end
  end
end
