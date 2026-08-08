# frozen_string_literal: true

require_relative "base"
require_relative "../../errors"

module MonoVM
  module Whois
    module Transport
      module Middleware
        # Retries failures that are plausibly transient.
        #
        # Only {ConnectionError} and {TimeoutError} qualify: a dropped TCP
        # connection or a slow registry is worth one more attempt. A
        # {ServerRefusedError} is not retried, and that restraint is the point — a
        # refusal usually *is* a rate limit, so hammering it makes the block worse
        # and delays every other lookup in the batch behind the backoff.
        class Retry < Middleware::Base
          DEFAULT_ATTEMPTS = 2
          DEFAULT_BACKOFF = 0.5

          RETRIABLE = [ConnectionError, TimeoutError].freeze

          attr_reader :attempts, :backoff

          # @param attempts [Integer] total tries, so 2 means one retry
          # @param backoff [Float] seconds before the first retry, doubling after
          # @param sleeper [#call] injectable so specs do not actually wait
          def initialize(app, attempts: DEFAULT_ATTEMPTS, backoff: DEFAULT_BACKOFF, sleeper: nil)
            @attempts = [attempts.to_i, 1].max
            @backoff = backoff
            @sleeper = sleeper || ->(seconds) { sleep(seconds) }
            super(app)
          end

          def fetch(query:, endpoint:)
            attempt = 0
            delay = backoff

            loop do
              attempt += 1

              begin
                return app.fetch(query: query, endpoint: endpoint)
              rescue *RETRIABLE
                raise if attempt >= attempts

                @sleeper.call(delay)
                delay *= 2
              end
            end
          end
        end
      end
    end
  end
end
