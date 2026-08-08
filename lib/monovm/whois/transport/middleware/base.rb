# frozen_string_literal: true

require_relative "../base"

module MonoVM
  module Whois
    module Transport
      # Cross-cutting behaviour, wrapped around a transport rather than built into it.
      #
      # Caching, throttling and retrying are decisions about how a whole system
      # talks to registries, not about how RDAP or port 43 works. Keeping them here
      # means {WhoisSocket} and {RdapHttp} stay small enough to read, and a caller
      # who wants a bare transport for one call can have one.
      module Middleware
        # Wraps another transport and forwards to it. Because it implements the same
        # {Transport::Base} interface, layers compose in any order and nothing
        # downstream can tell it is talking to a decorator.
        class Base < Transport::Base
          attr_reader :app

          class << self
            # A lambda suitable for {Factory}'s +middleware:+ list.
            #
            #   Factory.new(middleware: [Middleware::Cache.builder(ttl: 300)])
            def builder(**options)
              ->(app) { new(app, **options) }
            end
          end

          def initialize(app)
            @app = app
            super()
          end

          def fetch(query:, endpoint:)
            app.fetch(query: query, endpoint: endpoint)
          end

          def supports?(endpoint)
            app.supports?(endpoint)
          end

          # Reach the real transport through any stack of decorators.
          def unwrap
            app.is_a?(Base) ? app.unwrap : app
          end

          def inspect
            "#<#{self.class.name} -> #{app.inspect}>"
          end
        end
      end
    end
  end
end
