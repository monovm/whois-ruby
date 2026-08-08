# frozen_string_literal: true

require_relative "rule"
require_relative "rules/server_refusal"
require_relative "rules/wrong_registry"
require_relative "rules/rdap_object"
require_relative "rules/premium_name"
require_relative "rules/explicit_unavailability"
require_relative "rules/registration_fields"
require_relative "rules/registry_marker"
require_relative "rules/availability_keywords"
require_relative "rules/no_match"
require_relative "rules/tld_specific"
require_relative "rules/status_field"
require_relative "rules/recordless"

module MonoVM
  module Whois
    module Availability
      # The ordered chain of detection rules.
      #
      # Order is the whole design. Two invariants hold it together:
      #
      # 1. Rules that recognise a *non-answer* run first, so nothing that reaches the
      #    permissive rules could have been a refusal or a wrong-server reply.
      # 2. Every rule that concludes +:registered+ runs before every rule that
      #    concludes +:available+, so when two signals conflict the safe one wins.
      #    Selling a registered domain is a far worse failure than telling a customer
      #    to check again.
      #
      # The set is mutable so a host application can add a rule for a registry that
      # invents new wording, without forking the gem or waiting for a release.
      class RuleSet
        include Enumerable

        # The order shipped with the gem.
        def self.default
          new([
                Rules::ServerRefusal.new,          # non-answers first
                Rules::WrongRegistry.new,
                Rules::RdapObject.new,             # structured, authoritative
                Rules::PremiumName.new,            # premium is not available
                Rules::ExplicitUnavailability.new, # then everything meaning "registered"
                Rules::RegistrationFields.new,
                Rules::RegistryMarker.new,         # then everything meaning "available"
                Rules::AvailabilityKeywords.new,
                Rules::NoMatch.new,
                Rules::TldSpecific.new,
                Rules::StatusField.new,
                Rules::Recordless.new              # opt-in per TLD
              ])
        end

        def initialize(rules = [])
          @rules = rules.dup
        end

        def each(&)
          @rules.each(&)
        end

        def to_a
          @rules.dup
        end

        def size
          @rules.size
        end

        def names
          @rules.map(&:name)
        end

        # Add a rule at the very front, ahead of even the refusal checks.
        def prepend(rule)
          @rules.unshift(rule)
          self
        end

        # Add a rule at the very end, after the shipped fallbacks.
        def append(rule)
          @rules.push(rule)
          self
        end
        alias << append

        # Insert +rule+ immediately before the named rule, which is usually what you
        # want: a registry-specific check belongs next to the generic one it refines.
        #
        # @param name [String, Symbol] an existing rule's {Rule#name}
        # @raise [ArgumentError] when no rule has that name
        def insert_before(name, rule)
          @rules.insert(index_of!(name), rule)
          self
        end

        def insert_after(name, rule)
          @rules.insert(index_of!(name) + 1, rule)
          self
        end

        # Drop a shipped rule, for a deployment that disagrees with one of them.
        def remove(name)
          @rules.delete_at(index_of!(name))
          self
        end

        # Swap a rule's implementation, keeping its position.
        def replace(name, rule)
          @rules[index_of!(name)] = rule
          self
        end

        def include?(name)
          @rules.any? { |rule| rule.name == name.to_s }
        end

        def dup
          self.class.new(@rules)
        end

        def inspect
          "#<#{self.class.name} #{names.join(" -> ")}>"
        end

        private

        def index_of!(name)
          index = @rules.index { |rule| rule.name == name.to_s }
          raise ArgumentError, "no rule named #{name.inspect}; have #{names.join(", ")}" if index.nil?

          index
        end
      end
    end
  end
end
