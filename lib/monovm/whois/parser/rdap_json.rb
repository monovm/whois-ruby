# frozen_string_literal: true

require_relative "base"

module MonoVM
  module Whois
    module Parser
      # Parses an RDAP domain object (RFC 9083).
      #
      # RDAP is where structured data was the point, so this parser reads fields
      # instead of guessing at prose. Two parts of the format still need translating:
      # dates live in an +events+ array keyed by +eventAction+ rather than in named
      # fields, and contacts are jCard/vCard arrays (RFC 7095) — a nested array of
      # +[name, params, type, value]+ tuples that has to be walked to find an email.
      class RdapJson < Base
        # eventAction values mapped to the record fields they populate.
        EVENTS = {
          "registration" => :created_on,
          "last changed" => :updated_on,
          "last update of rdap database" => nil, # about the database, not the domain
          "expiration" => :expires_on
        }.freeze

        ROLES = {
          "registrant" => :registrant,
          "administrative" => :admin,
          "technical" => :tech,
          "billing" => :billing,
          "registrar" => :registrar
        }.freeze

        # jCard property name => the record field it populates. +adr+ is absent because
        # its value is a structured array rather than a plain string.
        VCARD_FIELDS = { "fn" => :fn, "org" => :org, "email" => :email, "tel" => :tel }.freeze

        def applicable?(response)
          document = response.json
          return false if document.nil?

          document.key?("objectClassName") || document.key?("ldhName") ||
            document.key?("rdapConformance")
        end

        def parse(response)
          document = response.json || {}
          events = extract_events(document)
          entities = extract_entities(document)
          registrar = entities[:registrar] || {}

          Record.new(
            domain: document["unicodeName"] || document["ldhName"],
            registry_id: document["handle"],
            registrar: registrar[:organization] || registrar[:name],
            registrar_iana_id: registrar[:iana_id],
            registrant: entities.dig(:registrant, :organization) || entities.dig(:registrant, :name),
            statuses: Array(document["status"]),
            nameservers: extract_nameservers(document),
            created_on: events[:created_on],
            updated_on: events[:updated_on],
            expires_on: events[:expires_on],
            dnssec: extract_dnssec(document),
            contacts: entities.except(:registrar),
            fields: document,
            source: name
          )
        end

        private

        def extract_events(document)
          Array(document["events"]).each_with_object({}) do |event, dates|
            next unless event.is_a?(Hash)

            field = EVENTS[event["eventAction"].to_s.downcase]
            next if field.nil?

            dates[field] ||= parse_time(event["eventDate"])
          end
        end

        def extract_nameservers(document)
          Array(document["nameservers"]).filter_map do |nameserver|
            next unless nameserver.is_a?(Hash)

            nameserver["unicodeName"] || nameserver["ldhName"]
          end
        end

        # +secureDNS.delegationSigned+ is the authoritative flag; report it in the
        # same vocabulary the WHOIS parsers use so callers need not special-case RDAP.
        def extract_dnssec(document)
          secure = document["secureDNS"]
          return nil unless secure.is_a?(Hash)

          signed = secure["delegationSigned"]
          return nil if signed.nil?

          signed ? "signedDelegation" : "unsigned"
        end

        def extract_entities(document)
          Array(document["entities"]).each_with_object({}) do |entity, contacts|
            next unless entity.is_a?(Hash)

            Array(entity["roles"]).each do |raw_role|
              role = ROLES[raw_role.to_s.downcase]
              next if role.nil?

              contacts[role] ||= entity_details(entity)
            end
          end
        end

        def entity_details(entity)
          card = parse_vcard(entity["vcardArray"])

          {
            handle: entity["handle"],
            name: card[:fn],
            organization: card[:org],
            email: card[:email],
            phone: card[:tel],
            country: card[:country],
            iana_id: public_id(entity, "IANA Registrar ID")
          }.compact
        end

        # A jCard is +["vcard", [[name, params, type, value], ...]]+ (RFC 7095).
        # Addresses carry a structured value whose seventh element is the country.
        def parse_vcard(vcard_array)
          entries = vcard_array.is_a?(Array) ? vcard_array[1] : nil
          return {} unless entries.is_a?(Array)

          entries.each_with_object({}) do |entry, card|
            next unless entry.is_a?(Array) && entry.length >= 4

            key = entry[0].to_s.downcase
            field = VCARD_FIELDS[key]

            if field
              card[field] ||= field == :org ? flatten_value(entry[3]) : entry[3].to_s
            elsif key == "adr"
              card[:country] ||= country_from(entry[3])
            end
          end
        end

        def flatten_value(value)
          value.is_a?(Array) ? value.flatten.compact.reject(&:empty?).first.to_s : value.to_s
        end

        def country_from(value)
          return nil unless value.is_a?(Array)

          country = value[6]
          country.to_s.strip.empty? ? nil : country.to_s.strip
        end

        def public_id(entity, type)
          Array(entity["publicIds"]).each do |public_id|
            next unless public_id.is_a?(Hash)
            return public_id["identifier"].to_s if public_id["type"].to_s.casecmp?(type)
          end

          nil
        end
      end
    end
  end
end
