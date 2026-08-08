# frozen_string_literal: true

require_relative "key_value"

module MonoVM
  module Whois
    module Parser
      # The ICANN Registrar Data Directory format used by gTLD registries.
      #
      # Structurally it is {KeyValue}, so almost everything is inherited. What earns a
      # subclass is that this format carries the same fact twice and the two copies
      # disagree: a +.com+ record holds both a +Registry Expiry Date+ and a
      # +Registrar Registration Expiration Date+, and the registrar's copy is
      # frequently stale. The registry is authoritative, so it wins here explicitly
      # rather than by luck of alias ordering.
      #
      # It also drops the +>>> Last update of WHOIS database+ trailer, which is a
      # timestamp for the database rather than for the domain and otherwise lands in
      # {Record#updated_on}.
      class IcannRdd < KeyValue
        # Keys that only this format uses; two of them together is a confident match.
        SIGNATURE_KEYS = [
          "registry domain id",
          "registrar whois server",
          "registrar iana id",
          "registry expiry date"
        ].freeze

        TRAILER = />>>\s*Last update of (?:the )?WHOIS database.*$/i

        def applicable?(response)
          return false if response.json?

          text = response.text.downcase
          SIGNATURE_KEYS.count { |key| text.include?("#{key}:") } >= 2
        end

        def parse(response)
          record = super

          # The registry's expiry date is authoritative; only fall back to the
          # registrar's if the registry did not supply one.
          expires = parse_time(record["registry expiry date"]) || record.expires_on

          Record.new(
            domain: record.domain,
            registry_id: record.registry_id,
            registrar: record.registrar,
            registrar_whois_server: record.registrar_whois_server,
            registrar_url: record.registrar_url,
            registrar_iana_id: record.registrar_iana_id,
            registrant: record.registrant,
            statuses: record.statuses.map { |status| strip_epp_url(status) },
            nameservers: record.nameservers,
            created_on: record.created_on,
            updated_on: record.updated_on,
            expires_on: expires,
            dnssec: record.dnssec,
            contacts: record.contacts,
            fields: record.fields,
            source: name
          )
        end

        private

        def extract_pairs(text)
          super(text.sub(TRAILER, ""))
        end

        # Statuses arrive as "clientTransferProhibited https://icann.org/epp#..." —
        # the URL is documentation, not part of the status.
        def strip_epp_url(status)
          status.split(/\s+/).first
        end
      end
    end
  end
end
