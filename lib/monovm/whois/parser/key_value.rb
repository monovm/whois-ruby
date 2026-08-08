# frozen_string_literal: true

require_relative "base"
require_relative "../availability/patterns"

module MonoVM
  module Whois
    module Parser
      # Parses the +Key: value+ shape that nearly every port 43 registry speaks.
      #
      # There is no standard for this format, only a strong convention, so the work
      # is in the disagreements: keys padded with dots to align values, the same field
      # called +Creation Date+, +created+, +registered on+ or +paid-till+, and fields
      # that legitimately repeat (a domain has several nameservers and several EPP
      # statuses). {ALIASES} is where that variation is absorbed; everything else here
      # is mechanical.
      class KeyValue < Base
        # +Key: value+, tolerating padded keys and values that contain colons.
        LINE = /\A(?<key>[^:]{1,64}?)[\s._·-]*:[ \t]*(?<value>.*)\z/

        # Canonical field name => the key spellings that mean it, most preferred
        # first. Order matters where a record carries two candidates: a gTLD record
        # has both a registry expiry date and the registrar's copy of it, and the
        # registry is authoritative.
        ALIASES = {
          domain: ["domain name", "domain", "ascii", "domain-name", "the domain"],
          registry_id: ["registry domain id"],
          registrar: ["registrar", "sponsoring registrar", "registrar name", "registrar organization"],
          registrar_whois_server: ["registrar whois server", "whois server"],
          registrar_url: ["registrar url", "referral url", "registrar web"],
          registrar_iana_id: ["registrar iana id"],
          registrant: [
            "registrant name", "registrant organization", "registrant organisation",
            "registrant", "holder", "holder name", "organisation", "organization", "org"
          ],
          created_on: [
            "creation date", "created", "created on", "created date", "registered on",
            "registration date", "registered", "domain registration date", "record created",
            "activation date"
          ],
          updated_on: [
            "updated date", "last updated", "last update", "changed", "modified",
            "last modified", "record last updated", "update date"
          ],
          expires_on: [
            "registry expiry date", "expiry date", "expiration date", "expires",
            "expires on", "expire date", "paid-till", "renewal date", "record expires",
            "registrar registration expiration date", "valid until", "expiry"
          ],
          dnssec: ["dnssec", "dnssec signed", "signed"]
        }.freeze

        # Fields that may appear many times; every occurrence is kept.
        MULTI = {
          statuses: ["domain status", "status", "state", "eppstatus"],
          nameservers: ["name server", "nameserver", "nserver", "ns", "dns", "name servers"]
        }.freeze

        # Contact blocks, addressed by key prefix: +Admin Email:+, +Tech Name:+.
        CONTACT_ROLES = {
          registrant: %w[registrant],
          admin: ["admin", "administrative contact", "admin contact"],
          tech: ["tech", "technical contact", "tech contact"],
          billing: ["billing", "billing contact"]
        }.freeze

        CONTACT_ATTRIBUTES = {
          name: "name",
          organization: "organization",
          email: "email",
          phone: "phone",
          country: "country",
          city: "city",
          state: "state/province"
        }.freeze

        def applicable?(response)
          return false if response.json?

          # LINE is anchored, so it has to be matched a line at a time — testing it
          # against the whole response fails on anything multi-line, which is every
          # real record.
          response.text.each_line.any? { |line| LINE.match?(line.strip) }
        end

        def parse(response)
          pairs = extract_pairs(response.text)

          Record.new(**attributes_from(pairs), fields: flatten(pairs), source: name)
        end

        private

        # {ALIASES}'s keys are deliberately {Record}'s keyword names, so resolving the
        # single-valued fields is one transform rather than a line each.
        def attributes_from(pairs)
          resolved = ALIASES.transform_values { |keys| first(pairs, keys) }

          resolved.merge(
            statuses: all(pairs, MULTI[:statuses]),
            nameservers: all(pairs, MULTI[:nameservers]),
            created_on: parse_time(resolved[:created_on]),
            updated_on: parse_time(resolved[:updated_on]),
            expires_on: parse_time(resolved[:expires_on]),
            contacts: extract_contacts(pairs)
          )
        end

        # @return [Hash{String => Array<String>}] normalised key => every value seen
        def extract_pairs(text)
          text.split("\n").each_with_object({}) do |raw_line, pairs|
            line = raw_line.strip
            next if line.empty? || comment?(line)

            match = LINE.match(line)
            next if match.nil?

            key = normalise_key(match[:key])
            value = match[:value].strip
            next if key.empty? || blank?(value)

            (pairs[key] ||= []) << value
          end
        end

        def comment?(line)
          Availability::Patterns::COMMENT_PREFIXES.any? { |prefix| line.start_with?(prefix) }
        end

        # Strip alignment padding, collapse inner whitespace, downcase.
        def normalise_key(key)
          key.strip.sub(/[\s.·]+\z/, "").gsub(/\s+/, " ").downcase
        end

        def first(pairs, keys)
          keys.each do |key|
            values = pairs[key]
            return values.first if values && !values.empty?
          end

          nil
        end

        def all(pairs, keys)
          keys.flat_map { |key| pairs[key] || [] }
        end

        def flatten(pairs)
          pairs.transform_values { |values| values.length == 1 ? values.first : values }
        end

        def extract_contacts(pairs)
          CONTACT_ROLES.each_with_object({}) do |(role, prefixes), contacts|
            details = contact_details(pairs, prefixes)
            contacts[role] = details unless details.empty?
          end
        end

        def contact_details(pairs, prefixes)
          CONTACT_ATTRIBUTES.each_with_object({}) do |(attribute, suffix), details|
            keys = prefixes.map { |prefix| "#{prefix} #{suffix}" }
            value = first(pairs, keys)
            details[attribute] = value unless value.nil?
          end
        end
      end
    end
  end
end
