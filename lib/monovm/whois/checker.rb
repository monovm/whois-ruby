# frozen_string_literal: true

require_relative "client"
require_relative "configuration"
require_relative "domain_name"

module MonoVM
  module Whois
    # Checks many domains, and expands a bare name across popular TLDs.
    #
    # Two jobs the single-domain {Client} deliberately does not do. Given +"monovm"+
    # with no TLD it tries +.com+, +.net+, +.org+ and +.info+; given a list it works
    # through it concurrently.
    #
    # Concurrency here is safe only because {Transport::Middleware::Throttle} sits
    # underneath it: eight threads against a list of +.com+ names would otherwise send
    # eight simultaneous queries to one Verisign host and get the caller's IP
    # rate-limited, after which every remaining answer is a refusal. The throttle is
    # per host, so a batch spanning many registries still runs genuinely in parallel.
    #
    #   MonoVM::Whois::Checker.whois("monovm.com")
    #   # => {"monovm.com" => :registered}
    #
    #   MonoVM::Whois::Checker.whois(["monovm", "google.com"])
    #   # => {"monovm.com" => :registered, "monovm.net" => :registered, ...}
    class Checker
      class << self
        # @param domains [String, Enumerable<String>]
        # @param options [Hash] +:popular_tlds+ (or +:popularTLDs+), +:concurrency+,
        #   plus anything {Configuration} accepts
        # @return [Hash{String => Symbol}] name => status
        def whois(domains, options = {})
          new(**build_options(options)).check(domains)
        end

        # As {.whois} but each value is the full {Result}.
        #
        # @return [Hash{String => Result}]
        def lookup(domains, options = {})
          new(**build_options(options)).check_detailed(domains)
        end

        private

        # Accept the PHP package's camelCase key alongside the Ruby one, and route
        # everything else at the configuration.
        def build_options(options)
          options = options.to_h.dup
          popular = options.delete(:popular_tlds) || options.delete(:popularTLDs)
          concurrency = options.delete(:concurrency)

          config = Configuration.new
          options.each do |key, value|
            setter = "#{key}="
            raise ArgumentError, "unknown option #{key.inspect}" unless config.respond_to?(setter)

            config.public_send(setter, value)
          end

          { config: config, popular_tlds: popular, concurrency: concurrency }.compact
        end
      end

      attr_reader :client, :popular_tlds, :concurrency

      def initialize(client: nil, config: nil, popular_tlds: nil, concurrency: nil)
        @config = config || Configuration.new
        @client = client || Client.new(config: @config)
        @popular_tlds = normalise_tlds(popular_tlds || @config.popular_tlds)
        @concurrency = (concurrency || @config.concurrency).to_i.clamp(1, 64)
      end

      # @return [Hash{String => Symbol}]
      def check(domains)
        check_detailed(domains).transform_values(&:status)
      end

      # @return [Hash{String => Result}]
      def check_detailed(domains)
        targets = expand(domains)
        return {} if targets.empty?

        results = run(targets)

        # Return in the order asked, which is what a caller rendering a table needs.
        targets.to_h { |name| [name.to_s, results[name.to_s]] }
      end

      private

      def normalise_tlds(tlds)
        list = tlds.is_a?(String) ? tlds.split(",") : Array(tlds)
        normalised = list.filter_map do |tld|
          cleaned = tld.to_s.strip.downcase.delete_prefix(".")
          cleaned.empty? ? nil : ".#{cleaned}"
        end

        raise ArgumentError, "popular_tlds must not be empty" if normalised.empty?

        normalised
      end

      # One input may become several names, and duplicates are looked up once.
      def expand(domains)
        inputs = domains.is_a?(String) ? [domains] : Array(domains)

        inputs.flat_map { |input| candidates_for(input) }.uniq(&:to_s)
      end

      def candidates_for(input)
        raise ArgumentError, "every domain must be a String, got #{input.class}" unless input.is_a?(String)

        name = DomainName.parse(input)

        # An unusable name is passed through untouched so the caller sees it reported
        # as :invalid under the string they supplied. Expanding it across the popular
        # TLDs first would turn one bad entry into four confusing ones.
        return [name] unless name.valid?
        return [name] unless name.bare?

        popular_tlds.map { |tld| name.join(tld) }
      end

      def run(targets)
        return sequential(targets) if concurrency == 1 || targets.length == 1

        queue = Queue.new
        targets.each { |name| queue << name }

        results = {}
        mutex = Mutex.new

        workers = Array.new([concurrency, targets.length].min) do
          Thread.new do
            while (name = pop(queue))
              result = safely(name) { client.lookup(name) }
              mutex.synchronize { results[name.to_s] = result }
            end
          end
        end

        workers.each(&:join)
        results
      end

      def sequential(targets)
        targets.to_h { |name| [name.to_s, safely(name) { client.lookup(name) }] }
      end

      def pop(queue)
        queue.pop(true)
      rescue ThreadError
        nil
      end

      # One unexpected failure must not lose the other 499 answers in a batch, and it
      # must not be reported as availability either.
      def safely(name)
        yield
      rescue StandardError => e
        Result.unknown(name, reason: "lookup raised #{e.class}: #{e.message}")
      end
    end
  end
end
