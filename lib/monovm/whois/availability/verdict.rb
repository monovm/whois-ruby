# frozen_string_literal: true

module MonoVM
  module Whois
    module Availability
      # The outcome of analysing one response.
      #
      # This is the central correction to the PHP package's design. There,
      # +isAvailable()+ returns a boolean, so "this domain is registered" and "the
      # server would not tell me" collapse into the same +false+ — and, worse, a
      # response that carries no verdict at all falls through the detector's
      # heuristics and comes back +true+. A rate-limited registry then reports
      # every registered domain as free to register.
      #
      # Here {#status} has four values and +:unknown+ is a real answer that is
      # never promoted to +:available+. {#rule} and {#trace} record *why*, which
      # is what makes a surprising classification debuggable.
      class Verdict
        STATUSES = %i[available registered premium unknown].freeze

        attr_reader :status, :rule, :reason, :evidence, :trace

        class << self
          STATUSES.each do |status|
            define_method(status) do |rule: nil, reason: nil, evidence: nil, trace: nil|
              new(status: status, rule: rule, reason: reason, evidence: evidence, trace: trace)
            end
          end
        end

        # @param status [Symbol] one of {STATUSES}
        # @param rule [String, nil] name of the rule that decided it
        # @param reason [String, nil] human-readable justification
        # @param evidence [String, nil] the matched text, trimmed for display
        # @param trace [Array<Hash>, nil] every rule consulted, in order
        def initialize(status:, rule: nil, reason: nil, evidence: nil, trace: nil)
          raise ArgumentError, "unknown verdict status #{status.inspect}" unless STATUSES.include?(status)

          @status = status
          @rule = rule
          @reason = reason
          @evidence = evidence
          @trace = (trace || []).freeze
          freeze
        end

        def available?
          status == :available
        end

        def registered?
          status == :registered
        end

        def premium?
          status == :premium
        end

        # True when no rule could reach a conclusion, or when the server refused
        # to answer. Callers must treat this as "ask again later", never as free.
        def unknown?
          status == :unknown
        end

        # True when the verdict says something actionable about the domain.
        def conclusive?
          !unknown?
        end

        # Return a copy carrying +trace+. Rules build verdicts without knowing the
        # trace; the analyzer attaches it once the chain finishes.
        def with_trace(trace)
          self.class.new(status: status, rule: rule, reason: reason, evidence: evidence, trace: trace)
        end

        def to_h
          {
            status: status,
            rule: rule,
            reason: reason,
            evidence: evidence
          }
        end

        def ==(other)
          other.is_a?(Verdict) && other.status == status && other.rule == rule
        end
        alias eql? ==

        def hash
          [self.class, status, rule].hash
        end

        def inspect
          "#<#{self.class.name} #{status}#{" by #{rule}" if rule}>"
        end
      end
    end
  end
end
