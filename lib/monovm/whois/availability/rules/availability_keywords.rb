# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # Plain-language phrases that state a name is unregistered.
        #
        # The list spans several languages, because ccTLD registries answer in their
        # own: +no se encontro el objeto+, +nicht vergeben+, +is vrij+. Matching is a
        # substring search over the commentary-stripped response — the stripping is
        # what keeps a phrase like "not found" in a registry's legal preamble from
        # being read as an answer.
        class AvailabilityKeywords < Rule
          def call(context)
            return nil if context.empty?

            keyword = context.find_keyword(Patterns::AVAILABILITY_KEYWORDS)
            return nil if keyword.nil?

            available(
              reason: "the response states the name is not registered",
              evidence: keyword
            )
          end
        end
      end
    end
  end
end
