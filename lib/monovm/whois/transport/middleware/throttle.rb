# frozen_string_literal: true

require_relative "base"

module MonoVM
  module Whois
    module Transport
      module Middleware
        # Keeps a minimum gap between consecutive queries to the same host.
        #
        # This is the politeness layer, and it is what makes concurrent bulk checks
        # safe. Registries publish query-rate limits and enforce them by blocking
        # clients; without a throttle, pointing eight threads at a list of +.com+
        # names sends eight simultaneous queries to one Verisign host and gets the
        # caller's IP throttled — after which every response is a refusal and no
        # domain can be checked at all.
        #
        # The gap is per host, not global, so a batch spanning many TLDs still runs
        # in parallel across them.
        class Throttle < Middleware::Base
          DEFAULT_INTERVAL = 0.5

          attr_reader :interval

          # @param interval [Float] minimum seconds between queries to one host
          # @param clock [#call] monotonic seconds, injectable for specs
          # @param sleeper [#call] receives seconds to wait, injectable for specs
          def initialize(app, interval: DEFAULT_INTERVAL, clock: nil, sleeper: nil)
            @interval = interval
            @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
            @sleeper = sleeper || ->(seconds) { sleep(seconds) }
            @last_seen = {}
            @mutex = Mutex.new
            super(app)
          end

          def fetch(query:, endpoint:)
            wait_for(endpoint.host)
            app.fetch(query: query, endpoint: endpoint)
          end

          private

          # Reserve this host's next slot while holding the lock, then sleep outside
          # it. Sleeping under the mutex would serialise every host behind whichever
          # one happened to be waiting.
          def wait_for(host)
            delay = @mutex.synchronize do
              now = @clock.call
              earliest = @last_seen[host]
              slot = earliest.nil? ? now : [now, earliest + interval].max
              @last_seen[host] = slot
              slot - now
            end

            @sleeper.call(delay) if delay.positive?
          end
        end
      end
    end
  end
end
