# frozen_string_literal: true

require_relative "../definition"
require_relative "../../errors"

module MonoVM
  module Whois
    module Registry
      module Sources
        # Interface for anything that can supply TLD definitions.
        #
        # {ServerRegistry} depends on this, not on files: that is what lets a host
        # application feed definitions from a database, an internal HTTP service or
        # a hard-coded hash in a test, without the registry knowing. A source needs
        # two methods, {#name} and {#load}.
        class Base
          # A short identifier recorded in {Definition#sources}, so a surprising
          # endpoint can be traced back to whichever source supplied it.
          #
          # @return [String]
          def name
            self.class.name.to_s.split("::").last.gsub(/([a-z])([A-Z])/, '\1_\2').downcase
          end

          # @return [Hash{String => Definition}] keyed by TLD, with the leading dot
          def load
            raise NotImplementedError, "#{self.class} must implement #load"
          end

          # Sources that cannot be read are usually optional (an override file that
          # does not exist yet). Returning true here lets {ServerRegistry} skip a
          # failure instead of aborting every lookup.
          def optional?
            false
          end

          private

          # Normalise +com+, +.COM+ or + .com + to +.com+.
          def normalise_tld(raw)
            cleaned = raw.to_s.strip.downcase.sub(/\A\.+/, "").sub(/\.+\z/, "")
            return nil if cleaned.empty?

            ".#{cleaned}"
          end

          # A TLD may be internationalised (.рф, .中国); definitions are keyed by the
          # ASCII form because that is what a resolved name is matched against.
          def ascii_tld(tld)
            return nil if tld.nil?

            DomainName.parse(tld.delete_prefix(".")).ascii.then { |ascii| ".#{ascii}" }
          end
        end
      end
    end
  end
end
