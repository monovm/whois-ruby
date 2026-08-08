# frozen_string_literal: true

module MonoVM
  module Whois
    # Base class for every error this gem raises.
    #
    # The PHP package throws bare +\Exception+ objects, so callers can only
    # rescue everything or nothing. Here the taxonomy is meaningful: callers who
    # just want "did it blow up" rescue {Error}, while callers that retry on a
    # busy registry but give up on a bad domain can discriminate.
    class Error < StandardError; end

    # The input is not a usable domain name.
    class InvalidDomainError < Error
      attr_reader :domain

      def initialize(domain, message = nil)
        @domain = domain
        super(message || "not a usable domain name: #{domain.inspect}")
      end
    end

    # No WHOIS or RDAP endpoint is known for this TLD.
    class UnsupportedTldError < Error
      attr_reader :tld

      def initialize(tld, message = nil)
        @tld = tld
        super(message || "no whois server known for #{tld.nil? ? "a name without a TLD" : tld}")
      end
    end

    # A server definition file is missing, unreadable or malformed.
    class DefinitionsError < Error; end

    # Raised when the transport could not reach the server at all.
    class ConnectionError < Error; end

    # The connection succeeded but the exchange exceeded the configured timeout.
    class TimeoutError < ConnectionError; end

    # The server answered, but refused to give a verdict: rate limiting, a
    # blocked client, a retired port 43 endpoint, or an HTTP status that is not
    # an answer (401/403/405/406/429/5xx).
    #
    # This is deliberately distinct from "the domain is registered". Conflating
    # the two is what makes the PHP original report registered domains as free.
    class ServerRefusedError < Error
      attr_reader :endpoint

      def initialize(message, endpoint: nil)
        @endpoint = endpoint
        super(message)
      end
    end

    # The server closed the connection without sending anything. An empty record
    # is not evidence that a domain is unregistered, so this is an error rather
    # than a verdict.
    class EmptyResponseError < Error; end
  end
end
