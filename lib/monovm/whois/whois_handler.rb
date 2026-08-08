# frozen_string_literal: true

require_relative "client"

module MonoVM
  module Whois
    # A single-domain handler that wraps one lookup in an object.
    #
    # Exists so that code written against camelCase WHOIS APIs reads the same way
    # here — the camelCase method names are aliased at the bottom.
    #
    #   handler = MonoVM::Whois::WhoisHandler.whois("monovm.com")
    #   handler.available?     # => false
    #   handler.whois_message  # => the raw registry response
    #   handler.record.expires_on
    #
    # One deliberate difference from boolean-style WHOIS APIs: there, an
    # +isAvailable()+ returns false both for a registered domain and for a
    # lookup that failed, and a permissive detector reports a rate-limited or
    # unreachable server as *available*. Here {#available?} is true only when availability was
    # positively established, and {#unknown?} exists to say "we could not find out".
    # Code that branches on +available?+ alone is safe; code that treats
    # +!available?+ as "registered" should ask {#registered?} instead.
    class WhoisHandler
      attr_reader :domain, :result

      class << self
        # @param domain [String]
        # @param options [Hash] anything {Configuration} accepts
        # @return [WhoisHandler]
        def whois(domain, **options)
          new(domain, **options)
        end
      end

      def initialize(domain, client: nil, **options)
        @domain = domain
        @client = client || build_client(options)
        @result = @client.lookup(domain)
      end

      # @return [String] the TLD, with its leading dot, or "" when none was resolved
      def tld
        result.tld.to_s
      end

      # @return [String] the second-level label, or "" when none was resolved
      def sld
        result.sld.to_s
      end

      # True only when the response positively established that the name is free.
      def available?
        result.available?
      end

      # True when the name exists. Distinct from +!available?+, which is also true
      # when the lookup failed.
      def registered?
        result.registered?
      end

      # True when the registry flagged the name as premium or reserved: unregistered,
      # but not obtainable at standard price.
      def premium?
        result.premium?
      end

      # True when no verdict could be reached — a refusal, a timeout, an unreadable
      # response. Ask again later; do not treat as free.
      def unknown?
        result.unknown?
      end

      # True when the domain was well-formed and its TLD is one we can look up.
      def valid?
        !result.invalid?
      end

      # The raw registry response, or the explanatory message when none was obtained.
      def whois_message
        result.whois_message
      end

      # @return [Parser::Record, nil]
      def record
        result.record
      end

      # @return [Symbol] :available, :registered, :premium, :unknown or :invalid
      def status
        result.status
      end

      # Which rule decided, what it matched, and what every other rule said —
      # the actual decision path rather than a fixed set of boolean flags.
      #
      # @return [Hash]
      def availability_details
        {
          domain: result.name,
          tld: result.tld,
          sld: result.sld,
          status: result.status,
          decided_by: result.verdict&.rule,
          reason: result.reason,
          evidence: result.verdict&.evidence,
          trace: result.verdict&.trace || [],
          endpoint: result.response&.endpoint&.to_s,
          response_length: result.response&.body&.length || 0,
          response_preview: preview
        }
      end

      def to_h
        result.to_h
      end

      def inspect
        "#<#{self.class.name} #{result.name.inspect} #{status}>"
      end

      # ------------------------------------------------------------------
      # camelCase aliases, for callers coming from camelCase WHOIS APIs
      # ------------------------------------------------------------------

      alias isAvailable available?
      alias isPremium premium?
      alias isValid valid?
      alias getTld tld
      alias getSld sld
      alias getWhoisMessage whois_message
      alias getAvailabilityDetails availability_details

      private

      def build_client(options)
        return Client.new if options.empty?

        config = Configuration.new
        options.each do |key, value|
          setter = "#{key}="
          raise ArgumentError, "unknown option #{key.inspect}" unless config.respond_to?(setter)

          config.public_send(setter, value)
        end

        Client.new(config: config)
      end

      def preview(limit = 200)
        text = whois_message.to_s.strip.gsub(/\s+/, " ")
        text.length > limit ? "#{text[0, limit]}..." : text
      end
    end
  end
end
