# frozen_string_literal: true

module MonoVM
  module Whois
    # What a lookup produced: the verdict, the parsed record, and the raw response
    # that backs both.
    #
    # {#status} adds +:invalid+ to the four {Availability::Verdict} statuses, for
    # names that never reached a server — malformed input, or a TLD with no known
    # endpoint. That distinction matters to a caller building a UI: +:invalid+ is
    # the user's problem to fix, +:unknown+ is ours to retry.
    class Result
      STATUSES = %i[available registered premium unknown invalid].freeze

      attr_reader :domain, :sld, :tld, :status, :verdict, :record, :response, :error

      class << self
        # A name that could not be looked up at all.
        def invalid(domain, reason:, sld: nil, tld: nil)
          new(domain: domain, status: :invalid, sld: sld, tld: tld, error: reason)
        end

        # A lookup that reached a server but produced no verdict.
        def unknown(domain, reason:, sld: nil, tld: nil, response: nil)
          new(
            domain: domain,
            status: :unknown,
            sld: sld,
            tld: tld,
            response: response,
            error: reason,
            verdict: Availability::Verdict.unknown(reason: reason)
          )
        end
      end

      def initialize(domain:, status:, sld: nil, tld: nil, verdict: nil, record: nil,
                     response: nil, error: nil)
        raise ArgumentError, "unknown result status #{status.inspect}" unless STATUSES.include?(status)

        @domain = domain
        @status = status
        @sld = sld
        @tld = tld
        @verdict = verdict
        @record = record
        @response = response
        @error = error
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

      def unknown?
        status == :unknown
      end

      def invalid?
        status == :invalid
      end

      # True when the lookup produced an actionable answer about the domain.
      def conclusive?
        available? || registered? || premium?
      end

      # The name as a string, in its Unicode form.
      def name
        domain.to_s
      end

      # The raw text the registry sent, or the explanatory message when no server
      # was reached. Named for the PHP package's +getWhoisMessage()+.
      def whois_message
        return response.text if response

        error.to_s
      end
      alias message whois_message

      # Why the verdict came out this way, for logging and bug reports.
      def reason
        verdict&.reason || error
      end

      def to_h
        {
          domain: name,
          sld: sld,
          tld: tld,
          status: status,
          reason: reason,
          rule: verdict&.rule,
          record: record&.to_h,
          response: response&.to_h
        }.compact
      end

      def inspect
        "#<#{self.class.name} #{name.inspect} #{status}>"
      end
    end
  end
end
