# frozen_string_literal: true

require_relative "rdap_json"
require_relative "icann_rdd"
require_relative "key_value"
require_relative "record"

module MonoVM
  module Whois
    module Parser
      # Picks the parser that understands a response.
      #
      # Ordered most specific first: RDAP JSON, then the ICANN gTLD format, then the
      # generic key/value fallback that handles everything else. Each parser decides
      # for itself whether it applies, so adding support for a registry with a genuinely
      # odd format means writing one parser and registering it — no changes here.
      #
      # Named +Selector+ rather than +Registry+ on purpose: {MonoVM::Whois::Registry}
      # already means "the TLD server registry", and two different Registry classes in
      # one library is a trap for whoever reads it next.
      class Selector
        def self.default
          new([RdapJson.new, IcannRdd.new, KeyValue.new])
        end

        attr_reader :parsers

        def initialize(parsers = [])
          @parsers = parsers.dup
        end

        # @param response [Response]
        # @return [Record] an empty record when nothing understood the response,
        #   which is normal: a not-found reply has no registration to parse
        def parse(response)
          parser = parser_for(response)
          return Record.new(source: nil) if parser.nil?

          parser.parse(response)
        rescue StandardError => e
          # A malformed record must not turn a successful lookup into an exception.
          # The verdict does not depend on parsing, so a failure here costs the
          # caller the structured fields and nothing else.
          Record.new(fields: { "parse_error" => "#{e.class}: #{e.message}" }, source: parser&.name)
        end

        # @return [Base, nil]
        def parser_for(response)
          parsers.find { |parser| parser.applicable?(response) }
        end

        # Add a parser ahead of the defaults.
        def prepend(parser)
          @parsers.unshift(parser)
          self
        end

        def append(parser)
          @parsers.push(parser)
          self
        end
        alias << append

        def names
          parsers.map(&:name)
        end

        def inspect
          "#<#{self.class.name} #{names.join(", ")}>"
        end
      end
    end
  end
end
