# frozen_string_literal: true

require_relative "patterns"

module MonoVM
  module Whois
    module Availability
      # Everything a rule needs to reach a verdict, prepared once.
      #
      # Ten rules run over the same response, and most of them want the same derived
      # forms of it: downcased, split into lines, stripped of registry commentary.
      # Computing those here rather than in each rule keeps the rules to a few lines
      # each and stops the same regexp work happening ten times per lookup.
      class Context
        attr_reader :response, :tld, :definition

        # @param response [Response, nil] nil when no server was reached
        # @param tld [String, nil] the matched suffix, with a leading dot
        # @param definition [Registry::Definition, nil]
        def initialize(response:, tld: nil, definition: nil)
          @response = response
          @tld = tld
          @definition = definition
        end

        # The response text with line endings normalised, or "" when absent.
        def text
          @text ||= response ? response.text : ""
        end

        def lower
          @lower ||= text.downcase
        end

        def empty?
          text.strip.empty?
        end

        def length
          text.length
        end

        # The parsed RDAP document, or nil.
        def json
          response&.json
        end

        def rdap?
          response ? response.rdap? : false
        end

        def http_status
          response&.status
        end

        def lines
          @lines ||= text.split("\n").map(&:strip)
        end

        # Lines that carry record data rather than registry commentary.
        #
        # This matters more than it looks. Registries put phrases like "not found"
        # and "no match" in their legal preamble, and a keyword scan over the raw
        # text picks those up and calls a registered domain free. Stripping comment
        # prefixes and known boilerplate first is what makes the keyword rules safe
        # enough to use at all.
        def significant_lines
          @significant_lines ||= lines.reject do |line|
            line.empty? ||
              Patterns::COMMENT_PREFIXES.any? { |prefix| line.start_with?(prefix) } ||
              Patterns::BOILERPLATE.any? { |pattern| pattern.match?(line) }
          end
        end

        def significant_text
          @significant_text ||= significant_lines.join("\n")
        end

        def significant_lower
          @significant_lower ||= significant_text.downcase
        end

        # @return [String, nil] the matched text, for use as verdict evidence
        def find(patterns, source: :text)
          subject = subject_for(source)

          patterns.each do |pattern|
            match = pattern.match(subject)
            return trim(match[0]) if match
          end

          nil
        end

        def match?(patterns, source: :text)
          !find(patterns, source: source).nil?
        end

        # @return [Integer] how many of +patterns+ appear at least once
        def count(patterns, source: :text)
          subject = subject_for(source)
          patterns.count { |pattern| pattern.match?(subject) }
        end

        # Substring search, for the plain keyword list.
        #
        # @return [String, nil] the keyword that matched
        def find_keyword(keywords, source: :significant)
          subject = source == :significant ? significant_lower : lower
          keywords.find { |keyword| subject.include?(keyword) }
        end

        # A short excerpt for diagnostics, so a surprising verdict can be explained
        # without dumping a whole record into a log.
        def preview(limit = 200)
          collapsed = text.strip.gsub(/\s+/, " ")
          collapsed.length > limit ? "#{collapsed[0, limit]}..." : collapsed
        end

        private

        def subject_for(source)
          case source
          when :significant then significant_text
          when :lower then lower
          else text
          end
        end

        def trim(matched)
          collapsed = matched.to_s.strip.gsub(/\s+/, " ")
          collapsed.length > 120 ? "#{collapsed[0, 120]}..." : collapsed
        end
      end
    end
  end
end
