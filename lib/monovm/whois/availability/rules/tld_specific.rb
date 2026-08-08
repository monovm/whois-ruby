# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # Per-TLD availability wording.
        #
        # Runs late because several entries are single words — +.it+ answers a free
        # name with little more than "available", +.ch+ with "we do not have an entry
        # in our database matching your query". As a general rule those would be far
        # too loose; scoped to one registry's output format they are reliable.
        #
        # By the time the chain gets here, every rule that could establish a
        # registration has already declined, so a loose availability pattern can only
        # fire on a response that carried no registration signal at all.
        class TldSpecific < Rule
          def call(context)
            return nil if context.empty? || context.tld.nil?

            patterns = Patterns::TLD_AVAILABILITY[context.tld]
            return nil if patterns.nil?

            matched = context.find(patterns, source: :significant)
            return nil if matched.nil?

            available(
              reason: "matched an availability pattern specific to #{context.tld}",
              evidence: matched
            )
          end
        end
      end
    end
  end
end
