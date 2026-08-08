# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # An explicit status field stating the name is free.
        #
        # Some detectors pair this check with a second inference: "fewer than two
        # registration fields present" also counts as availability. That inference is
        # unsound and is deliberately not reproduced. Every response that is not a
        # record has fewer than two registration fields — a rate-limit notice, a
        # blocked-client message, a legal preamble, a truncated read — so it converts
        # any non-answer into "free to register".
        #
        # Genuine availability always carries a positive signal, and the keyword,
        # not-found and per-TLD rules already look for it. The one case where silence
        # really is the only signal is handled by {Recordless}, which requires an
        # explicit per-TLD opt-in.
        class StatusField < Rule
          def call(context)
            return nil if context.empty?

            # An error or restriction notice can contain a status line while still
            # describing something that exists.
            return nil if context.match?(Patterns::ERROR_OR_RESTRICTION, source: :significant)

            matched = context.find(Patterns::STATUS_AVAILABLE, source: :significant)
            return nil if matched.nil?

            available(
              reason: "an explicit status field reports the name as available",
              evidence: matched
            )
          end
        end
      end
    end
  end
end
