# frozen_string_literal: true

require_relative "whois/version"
require_relative "whois/errors"
require_relative "whois/paths"
require_relative "whois/punycode"
require_relative "whois/domain_name"
require_relative "whois/endpoint"
require_relative "whois/response"
require_relative "whois/availability/verdict"
require_relative "whois/result"
require_relative "whois/registry/server_registry"
require_relative "whois/transport/factory"
require_relative "whois/availability/analyzer"
require_relative "whois/parser/selector"
require_relative "whois/configuration"
require_relative "whois/referral/follower"
require_relative "whois/client"
require_relative "whois/checker"
require_relative "whois/whois_handler"

module MonoVM
  # Domain WHOIS and RDAP lookups.
  #
  # The short way in:
  #
  #   MonoVM::Whois.available?("monovm.com")   # => false
  #   MonoVM::Whois.lookup("monovm.com")       # => #<Result "monovm.com" registered>
  #   MonoVM::Whois.whois(["monovm", "bing.com"])
  #
  # Settings are global unless overridden per call:
  #
  #   MonoVM::Whois.configure do |config|
  #     config.prefer = :whois          # port 43 before RDAP
  #     config.throttle_interval = 1.0  # be gentler with registries
  #     config.instrumentation = ->(event) { Rails.logger.info(event) }
  #   end
  module Whois
    class << self
      # The global configuration. Mutating it affects the shared {client}.
      def config
        @config ||= Configuration.new
      end

      # Yields {config} for editing, then discards the cached client so the next
      # lookup picks the changes up.
      #
      # @yieldparam config [Configuration]
      def configure
        yield config if block_given?
        reset_client!
        config
      end

      # Throw away the global configuration and client. Mainly for tests.
      def reset!
        @config = nil
        reset_client!
        self
      end

      # The shared client. Built once, because it owns the definition tables and the
      # caches and throttle clocks that make repeated lookups cheap and polite.
      def client
        @client || mutex.synchronize { @client ||= Client.new(config: config) }
      end

      # Look one domain up.
      #
      # @param domain [String]
      # @return [Result]
      def lookup(domain)
        client.lookup(domain)
      end

      # @return [Boolean] true only when availability was positively established.
      #   A refusal, a timeout or an unreadable response is false, not true.
      def available?(domain)
        client.available?(domain)
      end

      # @return [Boolean] true when the name is registered
      def registered?(domain)
        lookup(domain).registered?
      end

      # Check one or many domains, expanding a bare name across popular TLDs.
      #
      # @param domains [String, Enumerable<String>]
      # @param options [Hash]
      # @return [Hash{String => Symbol}] name => status
      def whois(domains, options = {})
        return Checker.new(client: client, config: config).check(domains) if options.empty?

        Checker.whois(domains, options)
      end

      # Full results rather than statuses.
      #
      # @return [Hash{String => Result}]
      def check(domains, options = {})
        return Checker.new(client: client, config: config).check_detailed(domains) if options.empty?

        Checker.lookup(domains, options)
      end

      # A single-domain handler object, camelCase aliases included.
      #
      # @return [WhoisHandler]
      def handler(domain, **options)
        WhoisHandler.whois(domain, **options)
      end

      # Why a lookup came out the way it did, including every rule consulted.
      #
      # @return [Hash]
      def explain(domain)
        client.explain(domain)
      end

      # @return [Array<String>] every TLD that can be looked up, dotted and sorted
      def supported_tlds
        config.server_registry.supported_tlds
      end

      # @return [Boolean]
      def supports?(tld)
        config.server_registry.supports?(tld)
      end

      private

      def reset_client!
        mutex.synchronize { @client = nil }
      end

      def mutex
        @mutex ||= Mutex.new
      end
    end
  end
end
