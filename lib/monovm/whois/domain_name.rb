# frozen_string_literal: true

require_relative "errors"
require_relative "punycode"

module MonoVM
  module Whois
    # An immutable, normalised domain name.
    #
    # This class knows about the *name* and nothing else: how to clean up what a
    # user pasted, how to move between Unicode and Punycode, and whether the
    # result is a legal host name. Deciding which part of it is the TLD needs the
    # server definitions, so that belongs to {Registry::ServerRegistry} — a name
    # cannot know on its own whether +.co.uk+ is a suffix or two labels.
    #
    #   name = DomainName.parse("  HTTPS://WWW.MÜNCHEN.de:8080/path?q=1  ")
    #   name.to_s   # => "www.münchen.de"
    #   name.ascii  # => "www.xn--mnchen-3ya.de"
    #   name.valid? # => true
    class DomainName
      ACE_PREFIX = "xn--"
      MAX_LENGTH = 253
      MAX_LABEL_LENGTH = 63

      # A single legal DNS label: alphanumeric ends, hyphens allowed inside.
      LABEL = /\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/

      attr_reader :input, :unicode

      class << self
        # Normalise +input+ into a name. Never raises: an unusable string yields
        # an instance whose {#valid?} is false, which is what bulk callers want so
        # one bad entry does not abort a batch.
        #
        # @param input [String]
        # @return [DomainName]
        def parse(input)
          raise InvalidDomainError, input unless input.is_a?(String)

          new(input)
        end

        # Like {.parse} but raises when the result is not a usable host name.
        #
        # @raise [InvalidDomainError]
        def parse!(input)
          parse(input).tap do |name|
            raise InvalidDomainError, input unless name.valid?
          end
        end
      end

      # Everything is computed here rather than memoised on demand, because the
      # instance is frozen: a value object that lazily fills in an ivar would raise
      # FrozenError the first time anyone asked for it.
      def initialize(input)
        @input = input
        @unicode = normalise(input).freeze
        @labels = @unicode.split(".", -1).freeze
        @ascii = @labels.map { |label| label_to_ascii(label) }.join(".").freeze
        @ascii_labels = @ascii.split(".", -1).freeze
        @valid = compute_valid?
        freeze
      end

      # The Unicode form — what a human reads.
      def to_s
        unicode
      end

      # The ASCII (Punycode) form — what goes on the wire and into URLs.
      #
      # Registries are queried in this form by default: Verisign answers "No match"
      # to a UTF-8 query, which would read as availability.
      attr_reader :ascii, :labels, :ascii_labels

      # True when every label is a legal DNS label and the whole name fits in a
      # DNS query. A single-label name like "monovm" is valid — callers append a
      # TLD to it — so this deliberately does not require a dot.
      def valid?
        @valid
      end

      # True when the name needed Punycode, i.e. it has non-ASCII labels.
      def idn?
        ascii != unicode
      end

      # True when the name carries no dot, so no TLD was supplied.
      def bare?
        !unicode.include?(".")
      end

      # Build a new name by appending +suffix+ to this one.
      #
      #   DomainName.parse("monovm").join(".com").to_s # => "monovm.com"
      def join(suffix)
        suffix = suffix.to_s
        suffix = ".#{suffix}" unless suffix.start_with?(".")
        self.class.parse("#{unicode}#{suffix}")
      end

      def ==(other)
        other.is_a?(DomainName) && other.unicode == unicode
      end
      alias eql? ==

      def hash
        [self.class, unicode].hash
      end

      def inspect
        "#<#{self.class.name} #{unicode.inspect}#{" invalid" unless valid?}>"
      end

      private

      # Reduce what people actually paste — URLs, mixed case, credentials, a
      # trailing root dot — down to a bare host name.
      def normalise(raw)
        text = raw.to_s.strip
        text = text.split("://", 2).last.to_s if text.include?("://")
        text = text.rpartition("@").last unless text.rpartition("@").last.empty?

        ["/", "?", "#"].each { |separator| text = text.split(separator, 2).first.to_s }

        # A bare colon is always a port here; an IPv6 literal is not a domain.
        text = text.split(":", 2).first.to_s

        text = text.strip.gsub(/\A\.+|\.+\z/, "")
        downcase(text)
      end

      # Unicode-aware downcasing plus NFC, so "MÜNCHEN" and a decomposed "münchen"
      # both reach Punycode as the same sequence of code points.
      def downcase(text)
        return text.downcase if text.ascii_only?

        text.unicode_normalize(:nfc).downcase
      rescue ArgumentError, Encoding::CompatibilityError
        # Invalid byte sequences cannot be normalised; leave them for #valid? to reject.
        text
      end

      def label_to_ascii(label)
        return label if label.ascii_only?

        "#{ACE_PREFIX}#{Punycode.encode(label)}"
      rescue Punycode::Error
        # Not convertible; hand it back unchanged so #valid? rejects the name
        # rather than this raising from a plain reader method.
        label
      end

      def compute_valid?
        return false if unicode.empty?

        candidate = ascii
        return false if candidate.empty? || candidate.length > MAX_LENGTH
        return false unless candidate.ascii_only?

        ascii_labels.all? do |label|
          !label.empty? && label.length <= MAX_LABEL_LENGTH && LABEL.match?(label)
        end
      end
    end
  end
end
