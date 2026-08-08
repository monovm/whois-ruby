# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # Last resort: the server answered with its banner and nothing else.
        #
        # A few registries — NIC Monaco among them — reply to an unregistered name
        # with no marker at all, just their header. For those, silence genuinely is
        # the signal, and no other rule can help.
        #
        # Inferring availability from absence is unsound in general, so this rule is
        # off unless a TLD definition sets +available_when_empty+, and even then it
        # refuses to answer if the response looks like anything other than a clean
        # empty reply: no registration fields, no refusal, no error or restriction
        # notice. Opt-in per TLD rather than a global fallback is the difference
        # between handling one registry's quirk and reporting every unreadable
        # response as free to register.
        class Recordless < Rule
          # Below two registration fields the response is not a record. At two or more
          # it is, however terse.
          MAX_FIELDS = 2

          def call(context)
            return nil unless context.definition&.available_when_empty?
            return nil if context.empty?
            return nil if context.match?(Patterns::ERROR_OR_RESTRICTION, source: :significant)

            fields = context.count(Patterns::REGISTRATION_FIELDS, source: :significant)
            return nil if fields >= MAX_FIELDS

            available(
              reason: "#{context.tld} answers unregistered names with no record, " \
                      "and this response carries none",
              evidence: context.preview(80)
            )
          end
        end
      end
    end
  end
end
