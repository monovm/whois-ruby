# frozen_string_literal: true

require_relative "base"

module MonoVM
  module Whois
    module Transport
      module Middleware
        # Reports every exchange to a subscriber.
        #
        # A registrar running this at volume needs to know which registries are slow
        # and which are refusing, and that is the host application's concern, not
        # this library's. So nothing is logged here — an event is handed to whatever
        # was injected, and the caller decides whether it becomes a log line, a
        # StatsD counter or nothing at all.
        class Instrumentation < Middleware::Base
          # @param subscriber [#call] receives one Hash per exchange
          def initialize(app, subscriber:)
            @subscriber = subscriber
            super(app)
          end

          def fetch(query:, endpoint:)
            started = Process.clock_gettime(Process::CLOCK_MONOTONIC)

            begin
              response = app.fetch(query: query, endpoint: endpoint)
            rescue StandardError => e
              publish(
                query: query,
                endpoint: endpoint,
                outcome: :error,
                error: e.class.name,
                message: e.message,
                elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
              )
              raise
            end

            publish(
              query: query,
              endpoint: endpoint,
              outcome: :ok,
              status: response.status,
              bytes: response.body.length,
              elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
            )
            response
          end

          private

          def publish(event)
            @subscriber.call(event.merge(endpoint: event[:endpoint].to_s, host: event[:endpoint].host))
          rescue StandardError
            # A broken metrics pipeline must never take a lookup down with it.
            nil
          end
        end
      end
    end
  end
end
