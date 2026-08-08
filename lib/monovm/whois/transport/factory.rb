# frozen_string_literal: true

require_relative "base"
require_relative "whois_socket"
require_relative "rdap_http"

module MonoVM
  module Whois
    module Transport
      # Chooses a transport for an endpoint.
      #
      # {Client} asks for "something that can fetch this endpoint" and gets it, so
      # adding a protocol means registering a transport here and nowhere else. The
      # factory also owns the middleware wrapping, which is why every transport it
      # hands out already caches, throttles and retries consistently — those are
      # decisions about the whole system, not about one protocol.
      class Factory
        attr_reader :transports, :middleware

        # @param transports [Array<Base>] candidates, asked in order via #supports?
        # @param middleware [Array<#call>] each receives a transport and returns a
        #   wrapped transport. Applied outermost-last, so the array reads in the
        #   order requests travel through it.
        def initialize(transports: nil, middleware: [])
          @transports = transports || [WhoisSocket.new, RdapHttp.new]
          @middleware = middleware
          @wrapped = {}
          @mutex = Mutex.new
        end

        # @param endpoint [Endpoint]
        # @return [Base] a transport that can serve +endpoint+, already wrapped
        # @raise [Error] when nothing registered can serve it
        def for(endpoint)
          transport = transports.find { |candidate| candidate.supports?(endpoint) }
          raise Error, "no transport can serve #{endpoint}" if transport.nil?

          # Middleware holds per-host state (throttle clocks, cache entries), so each
          # transport must be wrapped exactly once and shared, not re-wrapped per call.
          @wrapped[transport] || @mutex.synchronize { @wrapped[transport] ||= wrap(transport) }
        end

        private

        def wrap(transport)
          middleware.reverse.reduce(transport) { |inner, layer| layer.call(inner) }
        end
      end
    end
  end
end
