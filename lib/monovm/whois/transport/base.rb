# frozen_string_literal: true

require_relative "../response"
require_relative "../errors"

module MonoVM
  module Whois
    module Transport
      # The one interface every transport and every middleware implements.
      #
      #   fetch(query:, endpoint:) -> Response
      #
      # Two implementations exist for two protocols ({WhoisSocket}, {RdapHttp}), and
      # the middlewares in {Middleware} implement the same method so they can wrap
      # either one. Because the whole surface is a single method, the specs inject a
      # lambda-backed fake and the entire suite runs without a network.
      #
      # A transport decides nothing about availability. It returns what the server
      # said, or raises: {ConnectionError} when the server was unreachable,
      # {TimeoutError} when it was too slow, {ServerRefusedError} when it answered
      # but declined to give a verdict, {EmptyResponseError} when it said nothing.
      # That separation is what stops a network failure from being mistaken for an
      # unregistered domain.
      class Base
        # @param query [String] the name to ask about, already in wire form
        # @param endpoint [Endpoint] where to ask
        # @return [Response]
        def fetch(query:, endpoint:)
          raise NotImplementedError, "#{self.class} must implement #fetch"
        end

        # True when this transport can serve +endpoint+.
        #
        # @param endpoint [Endpoint]
        def supports?(endpoint)
          raise NotImplementedError, "#{self.class} must implement #supports?"
        end

        private

        # Wall-clock seconds for one exchange, recorded on the {Response} so callers
        # can see which registry is slow without instrumenting the caller.
        def measure
          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = yield
          [result, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
        end
      end
    end
  end
end
