# frozen_string_literal: true

require_relative "context"
require_relative "rule_set"
require_relative "verdict"

module MonoVM
  module Whois
    module Availability
      # Runs a response through the rule chain and returns the first verdict.
      #
      # The analyzer holds no detection logic of its own — it walks the {RuleSet},
      # stops at the first rule that answers, and records what every rule said on the
      # way. That trace is what turns "why does this say available?" from an
      # afternoon of guessing into one call to {#explain}.
      #
      # When no rule answers, the result is +:unknown+. That is the other half of the
      # correctness argument: the default is "I do not know", not "it is free".
      class Analyzer
        attr_reader :rules

        def initialize(rules: nil)
          @rules = rules || RuleSet.default
        end

        # @param response [Response, nil]
        # @param tld [String, nil]
        # @param definition [Registry::Definition, nil]
        # @return [Verdict]
        def analyze(response:, tld: nil, definition: nil)
          context = Context.new(response: response, tld: tld, definition: definition)
          run(context)
        end

        # Analyse and return the verdict together with every rule's outcome, for
        # debugging a surprising classification.
        #
        # @return [Hash]
        def explain(response:, tld: nil, definition: nil)
          context = Context.new(response: response, tld: tld, definition: definition)
          verdict = run(context)

          {
            status: verdict.status,
            decided_by: verdict.rule,
            reason: verdict.reason,
            evidence: verdict.evidence,
            trace: verdict.trace,
            tld: tld,
            response_length: context.length,
            response_preview: context.preview
          }
        end

        private

        def run(context)
          trace = []

          rules.each do |rule|
            begin
              verdict = rule.call(context)
            rescue StandardError => e
              # A rule that raises must not take the lookup down with it, and must
              # not be treated as a match either. Recording the failure keeps a
              # broken custom rule visible rather than silently skipped.
              trace << { rule: rule.name, matched: false, error: "#{e.class}: #{e.message}" }
              next
            end

            if verdict.nil?
              trace << { rule: rule.name, matched: false }
              next
            end

            trace << {
              rule: rule.name,
              matched: true,
              status: verdict.status,
              evidence: verdict.evidence
            }

            return verdict.with_trace(trace)
          end

          Verdict.unknown(reason: "no rule recognised this response", trace: trace)
        end
      end
    end
  end
end
