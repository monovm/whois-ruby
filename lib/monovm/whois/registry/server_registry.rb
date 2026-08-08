# frozen_string_literal: true

require_relative "definition"
require_relative "resolution"
require_relative "sources/base"
require_relative "sources/json_file"
require_relative "sources/iana_bootstrap"
require_relative "../domain_name"
require_relative "../paths"

module MonoVM
  module Whois
    module Registry
      # Answers two questions: which suffix of a name is its TLD, and how is that
      # TLD looked up.
      #
      # It owns no data of its own — definitions come from an ordered list of
      # {Sources::Base} objects, later sources overriding earlier ones. The default
      # order is bundled WHOIS list, then the IANA RDAP bootstrap, then an optional
      # user override file, so a deployment can correct a stale registry entry
      # without a gem release.
      class ServerRegistry
        attr_reader :sources

        class << self
          # The registry as most callers want it.
          #
          # @param override_path [String, nil] extra definitions, highest priority
          # @return [ServerRegistry]
          def default(override_path: Paths.override)
            sources = [
              Sources::JsonFile.new(path: Paths::WHOIS_SERVERS, name: "bundled"),
              Sources::IanaBootstrap.new
            ]

            if override_path
              sources << Sources::JsonFile.new(path: override_path, optional: true, name: "override")
            end

            new(sources: sources)
          end
        end

        # @param sources [Array<Sources::Base>] consulted in order; later wins
        def initialize(sources:)
          raise ArgumentError, "at least one source is required" if sources.nil? || sources.empty?

          @sources = sources
          @mutex = Mutex.new
        end

        # Every TLD this registry can look up, keyed with a leading dot.
        #
        # @return [Hash{String => Definition}]
        def definitions
          # Bulk checks resolve concurrently, and the first of those threads would
          # otherwise trigger this build several times over.
          @definitions || @mutex.synchronize { @definitions ||= build }
        end

        # @param tld [String, nil] with or without a leading dot
        # @return [Boolean]
        def supports?(tld)
          !definition_for(tld).nil?
        end

        # @param tld [String, nil]
        # @return [Definition, nil]
        def definition_for(tld)
          return nil if tld.nil?

          key = tld.to_s.strip.downcase
          key = ".#{key}" unless key.start_with?(".")
          definitions[key]
        end

        # @return [Array<String>] sorted, dotted TLDs
        def supported_tlds
          definitions.keys.sort
        end

        def size
          definitions.size
        end

        # Split +name+ at its longest known suffix.
        #
        # Longest-first is what makes multi-label suffixes and subdomains both land
        # on the registrable name: +example.co.uk+ resolves against +.co.uk+ rather
        # than +.uk+, and +www.example.com+ resolves to +example.com+ rather than
        # being queried as-is.
        #
        # @param name [DomainName, String]
        # @return [Resolution, nil] nil when no suffix of the name is known
        def resolve(name)
          domain = name.is_a?(DomainName) ? name : DomainName.parse(name)
          labels = domain.ascii_labels
          return nil if labels.length < 2

          # The Unicode labels line up one-for-one with the ASCII ones, so the split
          # found below can be applied to either form.
          unicode_labels = domain.labels

          # Start at the longest candidate suffix and shrink, so ".co.uk" is tried
          # before ".uk".
          (1...labels.length).each do |index|
            candidate = ".#{labels[index..].join(".")}"
            definition = definitions[candidate]
            next if definition.nil?

            return Resolution.new(
              domain: domain,
              sld: labels[index - 1],
              tld: candidate,
              definition: definition,
              registrable: registrable_from(unicode_labels, index)
            )
          end

          nil
        end

        # Drop the memoised definitions so the next call re-reads every source.
        # Mainly for tests and for long-running processes that refresh a data file.
        def reload
          @mutex.synchronize { @definitions = nil }
          self
        end

        def inspect
          "#<#{self.class.name} #{@definitions ? "#{@definitions.size} tlds" : "not loaded"} " \
            "sources=#{sources.map(&:name).join(",")}>"
        end

        private

        # Rebuild the registrable name from the Unicode labels, keeping the same split
        # point the ASCII match found. Returns nil if the two label lists somehow
        # disagree in length, in which case {Resolution} falls back to the ASCII form.
        def registrable_from(unicode_labels, index)
          return nil if index > unicode_labels.length - 1

          DomainName.parse([unicode_labels[index - 1], *unicode_labels[index..]].join("."))
        end

        def build
          merged = sources.each_with_object({}) do |source, accumulator|
            source.load.each do |tld, definition|
              existing = accumulator[tld]
              accumulator[tld] = existing ? existing.merge(definition) : definition
            end
          end

          if merged.empty?
            raise DefinitionsError,
                  "no definitions loaded from #{sources.map(&:name).join(", ")}"
          end

          merged.select { |_tld, definition| definition.usable? }.freeze
        end
      end
    end
  end
end
