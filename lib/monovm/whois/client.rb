# frozen_string_literal: true

require_relative "configuration"
require_relative "domain_name"
require_relative "result"
require_relative "parser/record"
require_relative "referral/follower"
require_relative "errors"

module MonoVM
  module Whois
    # Looks up one domain, end to end.
    #
    # The client owns the *sequence* — resolve the TLD, pick an endpoint, fetch,
    # classify, parse, maybe follow a referral — and none of the policy. Which server
    # serves a TLD is the registry's business, how to talk to it is the transport's,
    # what the answer means is the analyzer's, and what the record says is the
    # parser's. Every one of them arrives by injection, so a spec can replace any
    # single step without touching the others.
    #
    #   client = MonoVM::Whois::Client.new
    #   client.lookup("monovm.com").status  # => :registered
    class Client
      # Fields where the registrar's copy is the better one, used when a thin
      # registry's record is merged with the registrar's. Everywhere else the registry
      # wins, because it is authoritative for whether the name exists, what state it is
      # in and when it expires — and registrars are frequently stale on exactly those.
      # The registrant and the contact block are the reverse: a thin registry never has
      # them at all.
      REGISTRAR_WINS = %i[registrant contacts].freeze

      attr_reader :config, :server_registry, :transport_factory, :analyzer, :parsers, :follower

      # Every argument defaults from +config+; pass one to replace that collaborator.
      def initialize(config: nil, server_registry: nil, transport_factory: nil,
                     analyzer: nil, parsers: nil, follower: nil)
        @config = config || Configuration.new
        @server_registry = server_registry || @config.server_registry
        @transport_factory = transport_factory || @config.transport_factory
        @analyzer = analyzer || @config.analyzer
        @parsers = parsers || @config.parsers
        @follower = follower || default_follower
      end

      # @param domain [String, DomainName]
      # @return [Result] never raises for a lookup failure; the failure is the result
      def lookup(domain)
        name = domain.is_a?(DomainName) ? domain : DomainName.parse(domain)

        return Result.invalid(name, reason: "#{name} is not a valid domain name") unless name.valid?

        if name.bare?
          return Result.invalid(
            name,
            reason: "#{name} has no TLD; give one, or use Checker to try popular TLDs"
          )
        end

        resolution = server_registry.resolve(name)
        return Result.invalid(name, reason: "no WHOIS or RDAP server is known for #{name}") if resolution.nil?

        perform(name, resolution)
      end

      # @return [Boolean] true only when the lookup positively established availability
      def available?(domain)
        lookup(domain).available?
      end

      # Why a lookup came out the way it did, including every rule consulted.
      #
      # @return [Hash]
      def explain(domain)
        result = lookup(domain)

        {
          domain: result.name,
          status: result.status,
          tld: result.tld,
          reason: result.reason,
          trace: result.verdict&.trace || [],
          endpoint: result.response&.endpoint&.to_s,
          record: result.record&.to_h
        }
      end

      private

      def default_follower
        return nil unless config.follow_referrals

        Referral::Follower.new(transport_factory: transport_factory, max_hops: config.max_referrals)
      end

      def perform(name, resolution)
        response, failure = fetch_first(resolution)

        return failure_result(name, resolution, failure) if response.nil?

        verdict = analyzer.analyze(
          response: response,
          tld: resolution.tld,
          definition: resolution.definition
        )

        record = parsers.parse(response)
        record, response = enrich(record, response, resolution, verdict)

        Result.new(
          domain: name,
          status: verdict.status,
          sld: resolution.sld,
          tld: resolution.tld,
          verdict: verdict,
          record: record.empty? ? nil : record,
          response: response
        )
      end

      # Try the definition's endpoints in preference order, keeping the first answer.
      #
      # Falling through to port 43 when RDAP is unreachable is what keeps coverage
      # high: a registry that has an RDAP entry in the IANA bootstrap but whose
      # endpoint is broken still gets answered.
      #
      # @return [Array(Response, nil), Array(nil, Exception)]
      def fetch_first(resolution)
        endpoints = resolution.definition.endpoints(prefer: config.prefer)
        return [nil, UnsupportedTldError.new(resolution.tld)] if endpoints.empty?

        first_failure = nil

        endpoints.each do |endpoint|
          return [fetch(endpoint, resolution), nil]
        rescue Error => e
          # Remember the first failure: it came from the preferred endpoint and is
          # the more relevant one to report.
          first_failure ||= e
        end

        [nil, first_failure]
      end

      def fetch(endpoint, resolution)
        transport_factory.for(endpoint).fetch(
          query: query_for(endpoint, resolution),
          endpoint: endpoint
        )
      end

      # Punycode by default; the Unicode form for the few registries that insist on
      # it, and only over port 43 since a URL must be ASCII either way.
      def query_for(endpoint, resolution)
        if endpoint.socket? && config.unicode_query?(resolution.tld)
          resolution.registrable.to_s
        else
          resolution.query
        end
      end

      # Follow a thin registry's referral to fill in the record, keeping the
      # registry's verdict either way.
      def enrich(record, response, resolution, verdict)
        return [record, response] if follower.nil?
        return [record, response] unless verdict.registered?

        referral = follower.follow(response: response, record: record, query: resolution.query)
        return [record, response] if referral.nil?

        enriched = parsers.parse(referral)
        return [record, response] if enriched.empty?

        [merge_records(record, enriched), referral]
      end

      # Combine the registry's record with the registrar's, one policy stated once
      # rather than a conditional per field.
      def merge_records(registry_record, registrar_record)
        registry = registry_record.attributes
        registrar = registrar_record.attributes

        merged = registrar.merge(registry) do |key, from_registrar, from_registry|
          preferred, fallback =
            if REGISTRAR_WINS.include?(key)
              [from_registrar, from_registry]
            else
              [from_registry, from_registrar]
            end

          blank_value?(preferred) ? fallback : preferred
        end

        # Three fields are not a choice between two values.
        merged[:registrar_whois_server] = registry[:registrar_whois_server]
        merged[:fields] = registrar[:fields].merge(registry[:fields])
        merged[:source] = [registry_record.source, registrar_record.source].compact.uniq.join("+")

        Parser::Record.new(**merged)
      end

      def blank_value?(value)
        value.nil? || (value.respond_to?(:empty?) && value.empty?)
      end

      # Map a transport failure onto a result. The distinction being preserved here is
      # the one the PHP package loses: "we could not find out" is not "it is free".
      def failure_result(name, resolution, failure)
        case failure
        when UnsupportedTldError
          Result.invalid(
            name,
            reason: failure.message,
            sld: resolution.sld,
            tld: resolution.tld
          )
        else
          Result.unknown(
            name,
            reason: failure&.message || "the lookup produced no response",
            sld: resolution.sld,
            tld: resolution.tld
          )
        end
      end
    end
  end
end
