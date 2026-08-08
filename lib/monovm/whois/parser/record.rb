# frozen_string_literal: true

require "time"

module MonoVM
  module Whois
    module Parser
      # A registration, parsed into typed fields.
      #
      # The PHP package hands back the raw response and stops there, so every caller
      # that wants an expiry date writes its own regexp — once per registry format.
      # This is that work done once.
      #
      # {#fields} keeps every key/value the parser saw, so nothing is lost to the
      # normalisation: if a registry emits something this class has no accessor for,
      # it is still reachable.
      class Record
        # Values registries use to mean "withheld", mostly post-GDPR. Treated as
        # absent rather than reported as a registrant literally named "REDACTED FOR
        # PRIVACY", which would otherwise look like real data to a caller.
        REDACTIONS = [
          "redacted for privacy", "redacted", "not disclosed", "data protected",
          "privacy protected", "withheld for privacy", "statutory masking enabled",
          "gdpr masked", "non-public data", "not available", "n/a", "none"
        ].freeze

        attr_reader :domain, :registry_id, :registrar, :registrar_whois_server,
                    :registrar_url, :registrar_iana_id, :registrant, :statuses,
                    :nameservers, :created_on, :updated_on, :expires_on, :dnssec,
                    :contacts, :fields, :source

        def initialize(domain: nil, registry_id: nil, registrar: nil, registrar_whois_server: nil,
                       registrar_url: nil, registrar_iana_id: nil, registrant: nil, statuses: [],
                       nameservers: [], created_on: nil, updated_on: nil, expires_on: nil,
                       dnssec: nil, contacts: {}, fields: {}, source: nil)
          @domain = clean(domain)
          @registry_id = clean(registry_id)
          @registrar = clean(registrar)
          @registrar_whois_server = clean(registrar_whois_server)&.downcase
          @registrar_url = clean(registrar_url)
          @registrar_iana_id = clean(registrar_iana_id)
          @registrant = clean(registrant)
          @statuses = normalise_list(statuses).freeze
          @nameservers = normalise_nameservers(nameservers).freeze
          @created_on = created_on
          @updated_on = updated_on
          @expires_on = expires_on
          @dnssec = dnssec
          @contacts = contacts.freeze
          @fields = fields.freeze
          @source = source
          freeze
        end

        # The constructor's arguments, as a Hash. Lets a record be rebuilt with a few
        # fields changed — which is what merging a registry record with a registrar's
        # amounts to — without naming all sixteen fields at every call site.
        #
        # @return [Hash]
        def attributes
          {
            domain: domain, registry_id: registry_id, registrar: registrar,
            registrar_whois_server: registrar_whois_server, registrar_url: registrar_url,
            registrar_iana_id: registrar_iana_id, registrant: registrant,
            statuses: statuses, nameservers: nameservers, created_on: created_on,
            updated_on: updated_on, expires_on: expires_on, dnssec: dnssec,
            contacts: contacts, fields: fields, source: source
          }
        end

        # True when the parser found nothing worth reporting. A response can parse
        # cleanly and still be empty — a not-found reply, for instance.
        def empty?
          domain.nil? && registrar.nil? && nameservers.empty? && statuses.empty? &&
            created_on.nil? && expires_on.nil?
        end

        def dnssec?
          return false if dnssec.nil?

          !%w[unsigned unsigned delegation no false 0].include?(dnssec.to_s.downcase.strip)
        end

        # True when the registry says this name is locked against transfer.
        def transfer_prohibited?
          statuses.any? { |status| status.downcase.include?("transferprohibited") }
        end

        # True for any status meaning the registration is winding down.
        def expiring?
          statuses.any? do |status|
            normalised = status.downcase.delete(" ")
            normalised.include?("redemption") || normalised.include?("pendingdelete") ||
              normalised.include?("autorenewperiod")
          end
        end

        # Days until expiry, or nil when the record carries no expiry date.
        # Negative when the date has passed.
        def days_until_expiry(now: Time.now)
          return nil if expires_on.nil?

          ((expires_on - now) / 86_400).floor
        end

        # Look up a raw field by any of its names, case-insensitively.
        #
        #   record["Registry Expiry Date"]
        def [](key)
          wanted = key.to_s.downcase.strip
          _, value = fields.find { |name, _| name.to_s.downcase.strip == wanted }
          value
        end

        def to_h
          {
            domain: domain,
            registry_id: registry_id,
            registrar: registrar,
            registrar_whois_server: registrar_whois_server,
            registrar_url: registrar_url,
            registrar_iana_id: registrar_iana_id,
            registrant: registrant,
            statuses: statuses,
            nameservers: nameservers,
            created_on: created_on&.iso8601,
            updated_on: updated_on&.iso8601,
            expires_on: expires_on&.iso8601,
            dnssec: dnssec,
            contacts: contacts.empty? ? nil : contacts,
            source: source
          }.compact
        end

        def inspect
          "#<#{self.class.name} #{domain.inspect} registrar=#{registrar.inspect} " \
            "expires=#{expires_on&.iso8601.inspect}>"
        end

        private

        def clean(value)
          text = value.to_s.strip
          return nil if text.empty?
          return nil if REDACTIONS.include?(text.downcase)

          text
        end

        def normalise_list(values)
          Array(values).filter_map { |value| clean(value) }.uniq
        end

        # Registries pad nameservers with an IP address on the same line
        # (+ns1.example.com 192.0.2.1+) and disagree about case.
        def normalise_nameservers(values)
          Array(values).filter_map do |value|
            host = clean(value)&.split(/[\s,]+/)&.first
            host&.downcase&.delete_suffix(".")
          end.uniq
        end
      end
    end
  end
end
