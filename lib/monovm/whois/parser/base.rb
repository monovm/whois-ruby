# frozen_string_literal: true

require "time"
require_relative "record"

module MonoVM
  module Whois
    module Parser
      # Shared scaffolding for record parsers.
      #
      # Subclasses say which responses they understand ({#applicable?}) and how to
      # turn one into a {Record} ({#parse}). Date parsing lives here because it is
      # the one job every registry does differently and none of them do well: the
      # same field arrives as +2026-08-13T04:00:00Z+, +13-Aug-2026+, +2026.08.13+ or
      # +13/08/2026+, and getting it wrong by a month is worse than returning nil.
      class Base
        # @param response [Response]
        # @return [Boolean]
        def applicable?(response)
          raise NotImplementedError, "#{self.class} must implement #applicable?"
        end

        # @param response [Response]
        # @return [Record]
        def parse(response)
          raise NotImplementedError, "#{self.class} must implement #parse"
        end

        def name
          @name ||= Base.snake_case(self.class)
        end

        # +IcannRdd+ becomes +"icann_rdd"+. Handles an anonymous class, whose
        # +Module#name+ is nil — which a spec or a host application defining a parser
        # inline would otherwise crash on.
        def self.snake_case(klass)
          base = klass.name.to_s.split("::").last
          base = klass.inspect if base.nil? || base.empty?
          base.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
        end

        # Explicit formats, tried in order, before falling back to Ruby's parser.
        #
        # Ordering matters for the ambiguous ones: +13/08/2026+ is day-first
        # everywhere that writes it with slashes in a WHOIS record, so that pattern
        # comes before the month-first reading Time.parse would pick.
        DATE_FORMATS = [
          "%Y-%m-%dT%H:%M:%S%z",
          "%Y-%m-%dT%H:%M:%SZ",
          "%Y-%m-%dT%H:%M:%S.%L%z",
          "%Y-%m-%d %H:%M:%S%z",
          "%Y-%m-%d %H:%M:%S",
          "%Y-%m-%d",
          "%Y.%m.%d %H:%M:%S",
          "%Y.%m.%d",
          "%Y/%m/%d",
          "%d-%b-%Y %H:%M:%S",
          "%d-%b-%Y",
          "%d.%m.%Y %H:%M:%S",
          "%d.%m.%Y",
          "%d/%m/%Y %H:%M:%S",
          "%d/%m/%Y",
          "%b %d %Y",
          "%d %b %Y",
          "%Y%m%d"
        ].freeze

        # Registration dates are never before the DNS existed and never centuries
        # away. The range is what makes the ambiguous formats safe to try in order:
        # "%Y.%m.%d" happily parses "12.5.2015" as year 12, month 5, day 2015 —
        # rolling over into May of year 12 — and without this guard that nonsense wins
        # before "%d.%m.%Y" is ever tried, silently misdating every European record.
        PLAUSIBLE_YEARS = (1980..2200)

        private

        # @return [Time, nil]
        def parse_time(value)
          text = value.to_s.strip
          return nil if text.empty?

          # Registries append notes to dates: "2026-08-13 (registry lock)".
          text = text.sub(/\s*\(.*\)\s*\z/, "").strip
          # A trailing timezone name after an offset confuses every strptime format.
          text = text.sub(/\s+\((?:UTC|GMT)[^)]*\)\z/i, "").strip
          return nil if text.empty?

          from_formats(text) || from_fallback(text)
        end

        def from_formats(text)
          DATE_FORMATS.each do |format|
            parsed = begin
              Time.strptime(text, format)
            rescue ArgumentError, RangeError
              nil
            end

            next if parsed.nil?
            next unless PLAUSIBLE_YEARS.cover?(parsed.year)
            # strptime also parses "2026" with "%Y%m%d" and calls it January 1st;
            # requiring the year to appear in the input rejects that kind of match.
            next unless text.include?(parsed.year.to_s)

            return parsed
          end

          nil
        end

        def from_fallback(text)
          Time.parse(text)
        rescue ArgumentError, RangeError, TypeError
          nil
        end

        # Registries answer with a literal for "no data"; those must not become
        # strings that look like values.
        def blank?(value)
          text = value.to_s.strip
          text.empty? || Record::REDACTIONS.include?(text.downcase)
        end
      end
    end
  end
end
