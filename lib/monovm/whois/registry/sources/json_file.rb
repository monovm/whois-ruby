# frozen_string_literal: true

require "json"
require_relative "base"

module MonoVM
  module Whois
    module Registry
      module Sources
        # Reads the server-list JSON format: an array of entries, each mapping a
        # comma-separated +extensions+ list to one endpoint.
        #
        #   [
        #     {
        #       "extensions": ".com,.net",
        #       "uri": "socket://whois.verisign-grs.com",
        #       "available": "No match for",
        #       "premium": "Reserved",
        #       "rdap": "https://rdap.verisign.com/com/v1/domain/",
        #       "available_when_empty": false,
        #       "comment": "why this entry looks like this"
        #     }
        #   ]
        #
        # Both the bundled list and a user override file use this class — they
        # differ only in path and in whether a missing file is fatal.
        class JsonFile < Base
          attr_reader :path

          # @param path [String]
          # @param optional [Boolean] when true, a missing or unreadable file
          #   yields no definitions instead of raising
          # @param name [String, nil] identifier recorded on each definition
          def initialize(path:, optional: false, name: nil)
            @path = path
            @optional = optional
            @name = name
            super()
          end

          def name
            @name || (optional? ? "override" : "bundled")
          end

          def optional?
            @optional
          end

          # @return [Hash{String => Definition}]
          def load
            raw = read
            return {} if raw.nil?

            entries = parse(raw)
            entries.each_with_index.with_object({}) do |(entry, index), definitions|
              add_entry(definitions, entry, index)
            end
          end

          private

          def read
            return File.read(path, encoding: "UTF-8") if File.file?(path)
            return nil if optional?

            raise DefinitionsError, "server definitions not found at #{path}"
          rescue SystemCallError => e
            raise DefinitionsError, "cannot read #{path}: #{e.message}" unless optional?

            nil
          end

          def parse(raw)
            parsed = JSON.parse(raw)
            unless parsed.is_a?(Array)
              raise DefinitionsError, "#{path} must hold a JSON array, got #{parsed.class}"
            end

            parsed
          rescue JSON::ParserError => e
            raise DefinitionsError, "#{path} is not valid JSON: #{e.message}"
          end

          def add_entry(definitions, entry, index)
            unless entry.is_a?(Hash)
              raise DefinitionsError, "#{path}: entry #{index} must be an object, got #{entry.class}"
            end

            whois = build_endpoint(entry["uri"], index)
            rdap = build_endpoint(entry["rdap"], index)
            return if whois.nil? && rdap.nil?

            tlds_in(entry).each do |tld|
              definition = definition_for(tld, entry, whois, rdap)
              definitions[tld] = definitions.key?(tld) ? definitions[tld].merge(definition) : definition
            end
          end

          def tlds_in(entry)
            entry["extensions"].to_s.split(",").filter_map do |extension|
              ascii_tld(normalise_tld(extension))
            end
          end

          def definition_for(tld, entry, whois, rdap)
            Definition.new(
              tld: tld,
              whois_endpoint: whois,
              rdap_endpoint: rdap,
              available_match: entry["available"],
              premium_match: entry["premium"],
              available_when_empty: truthy?(entry["available_when_empty"]),
              comment: entry["comment"],
              sources: [name]
            )
          end

          def build_endpoint(uri, index)
            return nil if uri.nil? || uri.to_s.strip.empty?

            Endpoint.parse(uri)
          rescue DefinitionsError => e
            raise DefinitionsError, "#{path}: entry #{index} has a bad endpoint: #{e.message}"
          end

          # JSON gives real booleans, but hand-maintained files and environment
          # overrides tend to carry strings.
          def truthy?(value)
            return value if [true, false].include?(value)

            %w[1 true yes on].include?(value.to_s.strip.downcase)
          end
        end
      end
    end
  end
end
