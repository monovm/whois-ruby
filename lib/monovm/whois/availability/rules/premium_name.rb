# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The registry flagged the name as premium, reserved or otherwise withheld.
        #
        # A premium name is unregistered but not obtainable at standard price, and a
        # reserved one is not obtainable at all. Both are distinct from "available",
        # and a registrar showing an add-to-cart button for either has a support
        # ticket coming.
        #
        # The marker comes from the TLD definition, since the wording is registry
        # specific. This runs before the availability rules because those registries
        # tend to phrase a premium answer as a near-miss of "not found".
        class PremiumName < Rule
          def call(context)
            marker = context.definition&.premium_match
            return nil if marker.nil? || context.empty?

            return nil unless context.lower.include?(marker.downcase)

            premium(
              reason: "the registry marked this name as premium or reserved",
              evidence: marker
            )
          end
        end
      end
    end
  end
end
