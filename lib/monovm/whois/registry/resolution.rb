# frozen_string_literal: true

module MonoVM
  module Whois
    module Registry
      # A name split into its registrable parts, with the definition that serves it.
      #
      # Produced by {ServerRegistry#resolve}. Exists so the split and the definition
      # travel together: knowing that +example.co.uk+ has SLD +example+ is only
      # meaningful alongside the fact that +.co.uk+ is the suffix a registry
      # actually serves.
      class Resolution
        attr_reader :domain, :sld, :tld, :definition

        # @param domain [DomainName] the full name as queried
        # @param sld [String] the label immediately left of the suffix, ASCII
        # @param tld [String] the matched suffix, with a leading dot, ASCII — this is
        #   the key the definitions and the per-TLD pattern tables are indexed by
        # @param definition [Definition] how to look this suffix up
        # @param registrable [DomainName, nil] the registrable name in its *Unicode*
        #   form. Passed in because only the caller that did the splitting still knows
        #   the Unicode labels; rebuilding it from the ASCII +sld+ and +tld+ would
        #   lose them, and the registries that insist on Unicode over port 43 would
        #   silently be sent Punycode.
        def initialize(domain:, sld:, tld:, definition:, registrable: nil)
          @domain = domain
          @sld = sld
          @tld = tld
          @definition = definition
          # Built here, not memoised: the instance is frozen, so a lazy ivar would
          # raise FrozenError on first use.
          @registrable = registrable || DomainName.parse("#{sld}#{tld}")
          freeze
        end

        # The registrable name — the SLD plus its suffix, with any subdomain
        # dropped. A lookup for +www.example.co.uk+ must query +example.co.uk+,
        # because that is the object the registry holds. In Unicode form; call
        # {#query} for the wire form.
        attr_reader :registrable

        # The ASCII form to put on the wire.
        def query
          registrable.ascii
        end

        def to_h
          { domain: domain.to_s, sld: sld, tld: tld, registrable: registrable.to_s }
        end

        def inspect
          "#<#{self.class.name} #{sld}|#{tld}>"
        end
      end
    end
  end
end
