# frozen_string_literal: true

require_relative "../endpoint"

module MonoVM
  module Whois
    module Registry
      # Everything known about how to look up one TLD.
      #
      # A definition is assembled from several sources: the bundled server list
      # supplies the port 43 host and the registry's "available" marker, while the
      # IANA bootstrap supplies the RDAP base URL. {#merge} is what lets those
      # arrive independently and still end up on one object.
      class Definition
        attr_reader :tld, :whois_endpoint, :rdap_endpoint, :available_match,
                    :premium_match, :comment, :sources

        # @param tld [String] with the leading dot, e.g. +".co.uk"+
        # @param whois_endpoint [Endpoint, nil] port 43 endpoint
        # @param rdap_endpoint [Endpoint, nil] RDAP base URL endpoint
        # @param available_match [String, nil] literal the registry emits for an
        #   unregistered name; a fast pre-check, not the only signal
        # @param premium_match [String, nil] literal marking a premium/reserved name
        # @param available_when_empty [Boolean] registries that answer an
        #   unregistered name with nothing but their banner. Opt-in per TLD, because
        #   inferring availability from silence is unsound in general.
        # @param comment [String, nil] why this entry looks the way it does
        # @param sources [Array<String>] which sources contributed
        def initialize(tld:, whois_endpoint: nil, rdap_endpoint: nil, available_match: nil,
                       premium_match: nil, available_when_empty: false, comment: nil,
                       sources: [])
          @tld = tld
          @whois_endpoint = whois_endpoint
          @rdap_endpoint = rdap_endpoint
          @available_match = presence(available_match)
          @premium_match = presence(premium_match)
          @available_when_empty = available_when_empty
          @comment = presence(comment)
          @sources = sources.freeze
          freeze
        end

        def available_when_empty?
          @available_when_empty
        end

        def rdap?
          !rdap_endpoint.nil?
        end

        def whois?
          !whois_endpoint.nil?
        end

        # Endpoints to try, best first.
        #
        # RDAP goes first when available: its answer is structured JSON with an
        # explicit object class or an explicit +errorCode+, so availability is read
        # rather than guessed. Port 43 free text is the fallback.
        #
        # @param prefer [Symbol] +:rdap+ or +:whois+
        # @return [Array<Endpoint>]
        def endpoints(prefer: :rdap)
          ordered = prefer == :whois ? [whois_endpoint, rdap_endpoint] : [rdap_endpoint, whois_endpoint]
          ordered.compact
        end

        def usable?
          rdap? || whois?
        end

        # Combine with another definition for the same TLD. Values from +other+ win
        # where it has them, so later sources override earlier ones — that is how a
        # user's override file beats the bundled list.
        #
        # @param other [Definition]
        # @return [Definition]
        def merge(other)
          return self if other.nil?

          self.class.new(
            tld: tld,
            whois_endpoint: other.whois_endpoint || whois_endpoint,
            rdap_endpoint: other.rdap_endpoint || rdap_endpoint,
            available_match: other.available_match || available_match,
            premium_match: other.premium_match || premium_match,
            available_when_empty: other.available_when_empty? || available_when_empty?,
            comment: other.comment || comment,
            sources: (sources + other.sources).uniq
          )
        end

        def to_h
          {
            tld: tld,
            whois: whois_endpoint&.to_s,
            rdap: rdap_endpoint&.to_s,
            available_match: available_match,
            premium_match: premium_match,
            available_when_empty: available_when_empty?,
            sources: sources
          }.compact
        end

        def inspect
          "#<#{self.class.name} #{tld} whois=#{whois_endpoint&.host || "-"} " \
            "rdap=#{rdap_endpoint ? "yes" : "no"}>"
        end

        private

        def presence(value)
          text = value.to_s.strip
          text.empty? ? nil : text.freeze
        end
      end
    end
  end
end
