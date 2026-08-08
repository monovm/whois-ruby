# frozen_string_literal: true

require "uri"
require_relative "errors"

module MonoVM
  module Whois
    # Where a query gets sent, and over which protocol.
    #
    # Server definitions describe two very different things with one string:
    # +socket://whois.nic.uk+ is a host to open a TCP connection to, while
    # +https://rdap.verisign.com/com/v1/domain/+ is a URL prefix. This object
    # normalises both so {Transport::Factory} can pick a transport by asking
    # {#kind} rather than by re-parsing strings all over the codebase.
    class Endpoint
      SOCKET_SCHEME = "socket"
      DEFAULT_WHOIS_PORT = 43

      # Substituted with the queried name when present, so an unusual endpoint can
      # put the domain somewhere other than the end of the URL.
      PLACEHOLDER = "{domain}"

      attr_reader :uri, :scheme, :host, :port

      class << self
        # @param uri [String] e.g. +socket://whois.nic.uk+, +socket://host:4343+,
        #   or +https://rdap.example/domain/+
        # @return [Endpoint]
        # @raise [DefinitionsError] when the string is not a usable endpoint
        def parse(uri)
          raise DefinitionsError, "endpoint is empty" if uri.nil? || uri.to_s.strip.empty?

          new(uri.to_s.strip)
        end
      end

      def initialize(uri)
        @uri = uri
        @scheme = uri.split("://", 2).first.to_s.downcase
        parse_target!
        freeze
      end

      # True for port 43 WHOIS.
      def socket?
        scheme == SOCKET_SCHEME
      end

      # True for RDAP or any other HTTP-delivered service.
      def http?
        %w[http https].include?(scheme)
      end

      def tls?
        scheme == "https"
      end

      # A coarse label used to select a transport and to tag a {Response}.
      def kind
        socket? ? :whois : :rdap
      end

      # The URL to fetch for +name+. Only meaningful for HTTP endpoints.
      #
      #   Endpoint.parse("https://rdap.example/domain/").url_for("a.com")
      #   # => "https://rdap.example/domain/a.com"
      def url_for(name)
        raise DefinitionsError, "#{uri} is not an HTTP endpoint" unless http?
        return uri.sub(PLACEHOLDER, name) if uri.include?(PLACEHOLDER)

        "#{uri}#{name}"
      end

      def to_s
        uri
      end

      def ==(other)
        other.is_a?(Endpoint) && other.uri == uri
      end
      alias eql? ==

      def hash
        [self.class, uri].hash
      end

      def inspect
        "#<#{self.class.name} #{uri}>"
      end

      private

      def parse_target!
        if socket?
          parse_socket_target!
        elsif http?
          parse_http_target!
        else
          raise DefinitionsError, "unsupported endpoint scheme in #{uri.inspect}"
        end
      end

      # +socket://host+ or +socket://host:port+. A trailing slash is tolerated
      # because a few definition files carry one.
      def parse_socket_target!
        target = uri.split("://", 2).last.to_s.delete_suffix("/")
        host, _, port = target.rpartition(":")

        if host.empty? || !port.match?(/\A\d+\z/)
          @host = target
          @port = DEFAULT_WHOIS_PORT
        else
          @host = host
          @port = port.to_i
        end

        raise DefinitionsError, "no host in endpoint #{uri.inspect}" if @host.empty?
      end

      def parse_http_target!
        parsed = URI.parse(uri.sub(PLACEHOLDER, "placeholder"))
        raise DefinitionsError, "no host in endpoint #{uri.inspect}" if parsed.host.nil?

        @host = parsed.host
        @port = parsed.port
      rescue URI::InvalidURIError => e
        raise DefinitionsError, "invalid endpoint #{uri.inspect}: #{e.message}"
      end
    end
  end
end
