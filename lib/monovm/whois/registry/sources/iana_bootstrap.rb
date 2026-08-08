# frozen_string_literal: true

require "json"
require_relative "base"
require_relative "../../paths"

module MonoVM
  module Whois
    module Registry
      module Sources
        # The IANA RDAP bootstrap registry (RFC 7484).
        #
        # IANA publishes the authoritative TLD -> RDAP base URL map at
        # https://data.iana.org/rdap/dns.json. A snapshot ships with the gem, which
        # is why this library can answer for far more TLDs than a hand-maintained
        # port 43 list covers, and why those answers are structured JSON instead of
        # registry prose.
        #
        # The file looks like:
        #
        #   {
        #     "version": "1.0",
        #     "publication": "2026-07-23T02:00:03Z",
        #     "services": [
        #       [ ["com", "net"], ["https://rdap.verisign.com/com/v1/"] ]
        #     ]
        #   }
        #
        # Reading is deliberately offline. Fetching at load time would put a network
        # round trip in front of every process boot and make the library's own
        # startup depend on IANA being reachable; +rake data:refresh_rdap+ updates
        # the snapshot instead.
        class IanaBootstrap < Base
          BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

          # RDAP domain lookups live under +{base}/domain/{name}+ (RFC 7482 §3.1.3).
          DOMAIN_PATH = "domain/"

          attr_reader :path

          def initialize(path: Paths::RDAP_BOOTSTRAP, optional: true)
            @path = path
            @optional = optional
            super()
          end

          def name
            "iana-rdap"
          end

          def optional?
            @optional
          end

          # @return [String, nil] the snapshot's publication timestamp
          def published_at
            document&.fetch("publication", nil)
          end

          # @return [Hash{String => Definition}]
          def load
            services = document&.fetch("services", nil)
            return {} unless services.is_a?(Array)

            services.each_with_object({}) do |service, definitions|
              endpoint = endpoint_for(service)
              next if endpoint.nil?

              tlds_in(service).each do |tld|
                definitions[tld] ||= Definition.new(tld: tld, rdap_endpoint: endpoint, sources: [name])
              end
            end
          end

          private

          def document
            return @document if defined?(@document)

            @document = read_document
          end

          def read_document
            raw = read
            return nil if raw.nil?

            parsed = JSON.parse(raw)
            parsed.is_a?(Hash) ? parsed : nil
          rescue JSON::ParserError => e
            raise DefinitionsError, "#{path} is not valid JSON: #{e.message}" unless optional?

            nil
          end

          def read
            return File.read(path, encoding: "UTF-8") if File.file?(path)
            return nil if optional?

            raise DefinitionsError, "RDAP bootstrap not found at #{path}"
          rescue SystemCallError => e
            raise DefinitionsError, "cannot read #{path}: #{e.message}" unless optional?

            nil
          end

          # A service entry is +[[tld, ...], [url, ...]]+.
          def tlds_in(service)
            return [] unless service.is_a?(Array) && service[0].is_a?(Array)

            service[0].filter_map { |tld| ascii_tld(normalise_tld(tld)) }
          end

          def endpoint_for(service)
            return nil unless service.is_a?(Array) && service[1].is_a?(Array)

            url = preferred_url(service[1])
            return nil if url.nil?

            Endpoint.parse("#{url}#{DOMAIN_PATH}")
          rescue DefinitionsError
            # One malformed entry must not cost us the other 1,199.
            nil
          end

          # HTTPS where a registry offers both: RDAP responses carry registrant
          # data, and there is no reason to read it off the wire in clear text.
          def preferred_url(urls)
            candidates = urls.filter_map do |url|
              text = url.to_s.strip
              text.empty? ? nil : text
            end

            chosen = candidates.find { |url| url.start_with?("https://") } || candidates.first
            return nil if chosen.nil?

            chosen.end_with?("/") ? chosen : "#{chosen}/"
          end
        end
      end
    end
  end
end
