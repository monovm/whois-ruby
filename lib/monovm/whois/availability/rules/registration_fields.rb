# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # The response is a record: it carries the fields only a registration has.
        #
        # Useful for the many registries that never say "registered" in so many
        # words — they simply return the record, and the record's existence is the
        # answer. Counting fields rather than looking for one is deliberate: a
        # registrar name might appear in a preamble, but a registrar *and* a creation
        # date *and* nameservers together are a registration.
        class RegistrationFields < Rule
          # Three independent fields. Two is reachable by a chatty error notice; four
          # loses the GDPR-redacted records that only keep domain, registrar and
          # status.
          THRESHOLD = 3

          def call(context)
            return nil if context.empty?

            found = context.count(Patterns::REGISTRATION_INDICATORS, source: :significant)
            return nil if found < THRESHOLD

            registered(
              reason: "the response contains #{found} registration fields",
              evidence: context.find(Patterns::REGISTRATION_INDICATORS, source: :significant)
            )
          end
        end
      end
    end
  end
end
