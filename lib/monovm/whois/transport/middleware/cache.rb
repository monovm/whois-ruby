# frozen_string_literal: true

require_relative "base"

module MonoVM
  module Whois
    module Transport
      module Middleware
        # Remembers responses for a short while.
        #
        # Registries rate-limit, and a bulk check of a list that happens to contain
        # the same name twice should not pay for it twice. The TTL is deliberately
        # short by default: registration data changes, and a stale "available" is
        # the expensive kind of wrong.
        #
        # Only successful responses are cached. A failure is never remembered — a
        # transient timeout would otherwise poison every later lookup of that name.
        class Cache < Middleware::Base
          DEFAULT_TTL = 300.0
          DEFAULT_MAX_ENTRIES = 1_000

          attr_reader :ttl, :max_entries

          # @param ttl [Float] seconds an entry stays fresh
          # @param max_entries [Integer] cap on retained entries; oldest evicted first
          # @param clock [#call] monotonic seconds, injectable so specs need no sleeps
          def initialize(app, ttl: DEFAULT_TTL, max_entries: DEFAULT_MAX_ENTRIES, clock: nil)
            @ttl = ttl
            @max_entries = max_entries
            @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
            @entries = {}
            @mutex = Mutex.new
            super(app)
          end

          def fetch(query:, endpoint:)
            key = [endpoint.uri, query]

            cached = read(key)
            return cached if cached

            response = app.fetch(query: query, endpoint: endpoint)
            write(key, response)
            response
          end

          # @return [Integer] how many fresh entries are held
          def size
            @mutex.synchronize { @entries.size }
          end

          def clear
            @mutex.synchronize { @entries.clear }
            self
          end

          private

          def read(key)
            @mutex.synchronize do
              entry = @entries[key]
              next nil if entry.nil?

              if expired?(entry)
                @entries.delete(key)
                next nil
              end

              # Ruby hashes keep insertion order, so re-inserting makes this the
              # newest entry and keeps eviction least-recently-used.
              @entries.delete(key)
              @entries[key] = entry
              entry[:response]
            end
          end

          def write(key, response)
            @mutex.synchronize do
              @entries.delete(key)
              @entries[key] = { response: response, stored_at: @clock.call }
              @entries.shift while @entries.size > max_entries
            end
          end

          def expired?(entry)
            @clock.call - entry[:stored_at] > ttl
          end
        end
      end
    end
  end
end
