# frozen_string_literal: true

require_relative "verdict"
require_relative "patterns"

module MonoVM
  module Whois
    module Availability
      # One link in the detection chain.
      #
      # A rule answers a single question about a response and either returns a
      # {Verdict} — "I recognise this, here is the answer" — or +nil+, meaning
      # "not mine, ask the next one". That is the whole contract, and it is what
      # makes the chain extensible: a registry that invents new wording needs one
      # more small object, not a change to {Analyzer}.
      #
      #   class MyRule < Availability::Rule
      #     def call(context)
      #       return nil unless context.lower.include?("my special wording")
      #
      #       registered(reason: "registry said so")
      #     end
      #   end
      #
      #   MonoVM::Whois.configure { |c| c.rules.prepend(MyRule.new) }
      class Rule
        # Identifier used in {Verdict#rule} and in the analyzer's trace.
        # +ServerRefusal+ becomes +"server_refusal"+.
        #
        # An anonymous class has no +Module#name+, so a rule defined inline — which is
        # exactly how a host application tries one out — falls back to its inspect
        # form rather than crashing.
        def name
          @name ||= begin
            base = self.class.name.to_s.split("::").last
            base = self.class.inspect if base.nil? || base.empty?
            base.gsub(/([a-z\d])([A-Z])/, '\1_\2').downcase
          end
        end

        # @param context [Context]
        # @return [Verdict, nil]
        def call(context)
          raise NotImplementedError, "#{self.class} must implement #call"
        end

        private

        %i[available registered premium unknown].each do |status|
          define_method(status) do |reason: nil, evidence: nil|
            Verdict.public_send(status, rule: name, reason: reason, evidence: evidence)
          end
        end
      end
    end
  end
end
