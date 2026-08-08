# frozen_string_literal: true

require_relative "../endpoint"
require_relative "../errors"

module MonoVM
  module Whois
    module Referral
      # Chases a thin registry's pointer to the registrar's own WHOIS server.
      #
      # Verisign and the other thin registries hold almost nothing: query +.com+ and
      # the answer is a domain name, a status, nameservers, and a +Registrar WHOIS
      # Server+ line pointing at whoever sold it. The registrant, the contact details
      # and often the accurate expiry date are only on that second server. The PHP
      # package stops at the first answer and reports the thin record as the whole
      # truth.
      #
      # One deliberate constraint: a referral enriches the *record*, never the
      # verdict. The registry is authoritative about whether a name exists, and a
      # registrar's server that is down, rate-limiting or simply wrong must not be
      # able to turn a registered domain into an available one.
      class Follower
        # Registrars that answer but say nothing useful, or point in a circle.
        # Following these costs a round trip and a rate-limit slot for no data.
        SKIP_HOSTS = [
          "whois.iana.org",
          "whois.markmonitor.com",
          "not.applicable",
          "none"
        ].freeze

        attr_reader :transport_factory, :max_hops

        # @param transport_factory [Transport::Factory]
        # @param max_hops [Integer] referral hops to follow; 1 is almost always right
        def initialize(transport_factory:, max_hops: 1)
          @transport_factory = transport_factory
          @max_hops = max_hops
        end

        # @param response [Response] the registry's answer
        # @param record [Parser::Record] parsed from that answer
        # @param query [String] the name being looked up, in wire form
        # @return [Response, nil] the registrar's answer, or nil when there is no
        #   referral to follow or following it failed
        def follow(response:, record:, query:)
          return nil unless max_hops.positive?
          return nil unless response.whois?

          host = referral_host(record, response)
          return nil if host.nil?

          fetch(Endpoint.parse("socket://#{host}"), query)
        rescue DefinitionsError
          # The referral was not a usable host name; keep the registry's answer.
          nil
        end

        private

        def referral_host(record, response)
          host = record.registrar_whois_server
          host = host_from_text(response) if host.nil?
          return nil if host.nil?

          host = host.strip.downcase.sub(%r{\Ar?whois://}, "").split("/").first.to_s
          return nil if host.empty? || SKIP_HOSTS.include?(host)
          # A server that refers to itself would loop.
          return nil if host == response.endpoint.host.downcase
          return nil unless host.include?(".")

          host
        end

        # Some registries emit the referral without the exact key the parser knows.
        def host_from_text(response)
          match = response.text.match(/^\s*(?:Registrar\s+)?WHOIS\s+Server\s*:\s*(\S+)/i)
          match && match[1]
        end

        def fetch(endpoint, query)
          transport_factory.for(endpoint).fetch(query: query, endpoint: endpoint)
        rescue Error
          # A failed referral is not an error for the caller: the registry already
          # answered the question that matters.
          nil
        end
      end
    end
  end
end
