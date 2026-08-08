# frozen_string_literal: true

require_relative "registry/server_registry"
require_relative "transport/factory"
require_relative "transport/middleware/cache"
require_relative "transport/middleware/throttle"
require_relative "transport/middleware/retry"
require_relative "transport/middleware/instrumentation"
require_relative "availability/analyzer"
require_relative "availability/rule_set"
require_relative "parser/selector"
require_relative "paths"

module MonoVM
  module Whois
    # Every knob in one place, plus the defaults for the objects {Client} depends on.
    #
    # {Client} takes its collaborators by injection, which is what makes it testable
    # — but nobody wants to assemble a registry, a transport factory, an analyzer and
    # a parser selector just to look up one domain. This class is the seam between
    # those two needs: it holds the settings and builds sensible collaborators from
    # them, while leaving every one of them replaceable.
    #
    #   MonoVM::Whois.configure do |config|
    #     config.prefer = :whois
    #     config.throttle_interval = 1.0
    #     config.rules.insert_before("registry_marker", MyRule.new)
    #   end
    class Configuration
      # TLDs whose registry wants an internationalised name in Unicode rather than
      # Punycode, over port 43.
      #
      # DENIC answers +Status: invalid+ for +xn--mnchen-3ya.de+ but resolves
      # +münchen.de+ correctly. Almost every other registry is the reverse — Verisign
      # answers "No match" to a UTF-8 query, which reads as availability — so
      # Punycode is the default and this is the short exception list. URLs are always
      # ASCII, so it never applies to RDAP.
      DEFAULT_UNICODE_QUERY_TLDS = [".de"].freeze

      # Tried in order when a name arrives without a TLD.
      DEFAULT_POPULAR_TLDS = [".com", ".net", ".org", ".info"].freeze

      # Transport
      attr_accessor :socket_connect_timeout, :socket_read_timeout,
                    :http_open_timeout, :http_read_timeout, :verify_ssl, :user_agent

      # Behaviour
      attr_accessor :prefer, :follow_referrals, :max_referrals, :unicode_query_tlds,
                    :popular_tlds, :concurrency, :override_path

      # Middleware
      attr_accessor :cache, :cache_ttl, :cache_max_entries,
                    :throttle_interval, :retry_attempts, :retry_backoff, :instrumentation

      # Injected collaborators; each defaults lazily and can be replaced outright.
      attr_writer :server_registry, :transport_factory, :analyzer, :rules, :parsers

      def initialize
        @socket_connect_timeout = Transport::WhoisSocket::DEFAULT_CONNECT_TIMEOUT
        @socket_read_timeout = Transport::WhoisSocket::DEFAULT_READ_TIMEOUT
        @http_open_timeout = Transport::RdapHttp::DEFAULT_OPEN_TIMEOUT
        @http_read_timeout = Transport::RdapHttp::DEFAULT_READ_TIMEOUT
        @verify_ssl = true
        @user_agent = nil

        # RDAP first: a structured answer beats pattern-matching registry prose.
        @prefer = :rdap
        @follow_referrals = true
        @max_referrals = 1
        @unicode_query_tlds = DEFAULT_UNICODE_QUERY_TLDS.dup
        @popular_tlds = DEFAULT_POPULAR_TLDS.dup
        @concurrency = 8
        @override_path = Paths.override

        @cache = true
        @cache_ttl = Transport::Middleware::Cache::DEFAULT_TTL
        @cache_max_entries = Transport::Middleware::Cache::DEFAULT_MAX_ENTRIES
        @throttle_interval = Transport::Middleware::Throttle::DEFAULT_INTERVAL
        @retry_attempts = Transport::Middleware::Retry::DEFAULT_ATTEMPTS
        @retry_backoff = Transport::Middleware::Retry::DEFAULT_BACKOFF
        @instrumentation = nil
      end

      def server_registry
        @server_registry ||= Registry::ServerRegistry.default(override_path: override_path)
      end

      def rules
        @rules ||= Availability::RuleSet.default
      end

      def analyzer
        @analyzer ||= Availability::Analyzer.new(rules: rules)
      end

      def parsers
        @parsers ||= Parser::Selector.default
      end

      def transport_factory
        @transport_factory ||= Transport::Factory.new(
          transports: default_transports,
          middleware: default_middleware
        )
      end

      # True when +tld+'s registry wants the Unicode form over port 43.
      def unicode_query?(tld)
        unicode_query_tlds.include?(tld)
      end

      # A copy, so a per-call override cannot mutate the global default.
      def dup
        copy = super
        copy.unicode_query_tlds = unicode_query_tlds.dup
        copy.popular_tlds = popular_tlds.dup
        copy
      end

      private

      def default_transports
        [
          Transport::WhoisSocket.new(
            connect_timeout: socket_connect_timeout,
            read_timeout: socket_read_timeout
          ),
          Transport::RdapHttp.new(
            open_timeout: http_open_timeout,
            read_timeout: http_read_timeout,
            verify_ssl: verify_ssl,
            user_agent: user_agent
          )
        ]
      end

      # Order matters, and it reads outermost first. Instrumentation sees everything
      # including cache hits; the cache answers before a throttle delay is paid;
      # retries happen closest to the wire so a retried attempt is still throttled.
      def default_middleware
        layers = []
        if instrumentation
          layers << Transport::Middleware::Instrumentation.builder(subscriber: instrumentation)
        end
        if cache
          layers << Transport::Middleware::Cache.builder(ttl: cache_ttl,
                                                         max_entries: cache_max_entries)
        end
        if throttle_interval.to_f.positive?
          layers << Transport::Middleware::Throttle.builder(interval: throttle_interval)
        end
        if retry_attempts.to_i > 1
          layers << Transport::Middleware::Retry.builder(attempts: retry_attempts,
                                                         backoff: retry_backoff)
        end
        layers
      end
    end
  end
end
