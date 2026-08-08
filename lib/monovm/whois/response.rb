# frozen_string_literal: true

require "json"

module MonoVM
  module Whois
    # One raw answer from one server.
    #
    # Transports return this; availability rules and parsers read it. Keeping the
    # raw body verbatim matters — callers of a WHOIS library legitimately want to
    # see exactly what the registry said, so nothing here mutates {#body}.
    class Response
      attr_reader :body, :endpoint, :query, :status, :elapsed

      # @param body [String] exactly what the server sent
      # @param endpoint [Endpoint] where it came from
      # @param query [String] the name that was asked about
      # @param status [Integer, nil] HTTP status, nil for port 43
      # @param elapsed [Float, nil] seconds spent on the exchange
      def initialize(body:, endpoint:, query:, status: nil, elapsed: nil)
        @body = body.to_s.freeze
        @endpoint = endpoint
        @query = query
        @status = status
        @elapsed = elapsed
      end

      # Not frozen as a whole: {#text} and {#json} are memoised, and parsing a large
      # RDAP document on every rule that asks for it would be wasted work. The body
      # itself is frozen, so the response is still effectively immutable.

      def rdap?
        endpoint.kind == :rdap
      end

      def whois?
        endpoint.kind == :whois
      end

      def empty?
        body.strip.empty?
      end

      # The body as text, with line endings normalised to \n. Availability rules
      # match against this so a pattern anchored to a line start behaves the same
      # whether the registry sent CRLF or LF.
      def text
        @text ||= body.encode("UTF-8", invalid: :replace, undef: :replace, replace: "")
                      .gsub(/\r\n?/, "\n")
                      .freeze
      end

      # The parsed RDAP document, or nil when the body is not JSON.
      #
      # Memoised including the nil case: a non-JSON body is re-checked by several
      # rules and reparsing it each time is wasted work.
      def json
        return @json if defined?(@json)

        @json = begin
          parsed = JSON.parse(body)
          parsed.is_a?(Hash) ? parsed : nil
        rescue JSON::ParserError
          nil
        end
      end

      def json?
        !json.nil?
      end

      def to_h
        {
          query: query,
          endpoint: endpoint.to_s,
          kind: endpoint.kind,
          status: status,
          elapsed: elapsed,
          length: body.length
        }
      end

      def inspect
        "#<#{self.class.name} query=#{query.inspect} endpoint=#{endpoint} " \
          "status=#{status.inspect} bytes=#{body.length}>"
      end
    end
  end
end
