# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The exact string this registry emits for an unregistered name, taken from
        # the TLD definition.
        #
        # This is the curated, high-confidence signal — +"No match for"+ for Verisign,
        # +"Domain not found"+ for PIR — and the PHP package checks it first, before
        # anything else.
        #
        # Here it runs *after* the rules that establish a registration, and that
        # reordering fixes a real failure mode: when a TLD is mapped to the wrong
        # server, or a registry starts returning a record that happens to contain the
        # marker text, checking the marker first turns a registered domain into an
        # available one. Letting a genuine record win first costs nothing, because a
        # response cannot both be a record and be the registry's not-found message.
        class RegistryMarker < Rule
          def call(context)
            marker = context.definition&.available_match
            return nil if marker.nil? || context.empty?

            return nil unless context.significant_lower.include?(marker.downcase)

            available(
              reason: "matched the not-found marker configured for #{context.tld}",
              evidence: marker
            )
          end
        end
      end
    end
  end
end
