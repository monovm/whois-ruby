# frozen_string_literal: true

require "json"
require "optparse"
require_relative "../whois"

module MonoVM
  module Whois
    # The +monovm-whois+ command.
    #
    # Kept as a class taking explicit +stdout+/+stderr+ and returning an exit code
    # rather than calling +exit+ itself, so the specs can run it in-process and assert
    # on its output.
    #
    # Exit codes: 0 when every name got a real answer, 1 when any came back unknown or
    # invalid, 2 for a usage error.
    class CLI
      EXIT_OK = 0
      EXIT_INCONCLUSIVE = 1
      EXIT_USAGE = 2

      # Terminal colours, skipped when output is redirected.
      COLOURS = {
        available: "\e[32m",  # green
        registered: "\e[31m", # red
        premium: "\e[33m",    # yellow
        unknown: "\e[35m",    # magenta
        invalid: "\e[90m"     # grey
      }.freeze
      RESET = "\e[0m"

      def self.run(argv, stdout: $stdout, stderr: $stderr)
        new(stdout: stdout, stderr: stderr).run(argv)
      end

      def initialize(stdout: $stdout, stderr: $stderr)
        @stdout = stdout
        @stderr = stderr
        @options = default_options
      end

      def run(argv)
        domains = parser.parse(argv)

        return print_help if @options[:help]
        return print_version if @options[:version]
        return print_tld_count if @options[:tld_count]
        return usage_error("give at least one domain name") if domains.empty?

        results = check(domains)
        render(results)
        exit_code(results)
      rescue OptionParser::ParseError => e
        usage_error(e.message)
      rescue Error => e
        @stderr.puts "monovm-whois: #{e.message}"
        EXIT_INCONCLUSIVE
      rescue Interrupt
        @stderr.puts "monovm-whois: interrupted"
        EXIT_INCONCLUSIVE
      end

      private

      def default_options
        {
          format: :text,
          details: false,
          raw: false,
          prefer: :rdap,
          cache: true,
          concurrency: nil,
          timeout: nil,
          popular_tlds: nil,
          colour: nil
        }
      end

      # Memoised: the option handlers close over @options, and building a second
      # parser to print usage would be wasteful and easy to let drift.
      def parser
        @parser ||= OptionParser.new do |opts|
          opts.banner = "Usage: monovm-whois DOMAIN [DOMAIN...] [options]"
          opts.separator ""
          opts.separator "Checks domain availability over RDAP and WHOIS."
          opts.separator ""

          opts.on("-j", "--json", "Emit JSON instead of a table") { @options[:format] = :json }
          opts.on("-d", "--details", "Show which rule decided, and why") { @options[:details] = true }
          opts.on("-r", "--raw", "Print the raw registry response") { @options[:raw] = true }

          opts.on("--prefer PROTOCOL", %w[rdap whois],
                  "Try rdap or whois first (default: rdap)") do |value|
            @options[:prefer] = value.to_sym
          end

          opts.on("-t", "--timeout SECONDS", Float, "Per-request timeout") do |value|
            @options[:timeout] = value
          end

          opts.on("-c", "--concurrency N", Integer, "Parallel lookups (default: 8)") do |value|
            @options[:concurrency] = value
          end

          opts.on("--tlds LIST", "TLDs to try for a name with no TLD",
                  "(default: .com,.net,.org,.info)") do |value|
            @options[:popular_tlds] = value.split(",")
          end

          opts.on("--[no-]cache", "Cache responses in-process (default: on)") do |value|
            @options[:cache] = value
          end

          opts.on("--[no-]color", "--[no-]colour", "Colourise the status column") do |value|
            @options[:colour] = value
          end

          opts.on("--tld-count", "Print how many TLDs are supported, then exit") do
            @options[:tld_count] = true
          end

          opts.on("-v", "--version", "Print the version, then exit") do
            @options[:version] = true
          end

          opts.on("-h", "--help", "Print this message") { @options[:help] = true }
        end
      end

      def print_help
        @stdout.puts parser
        EXIT_OK
      end

      def print_version
        @stdout.puts "monovm-whois #{MonoVM::Whois::VERSION}"
        EXIT_OK
      end

      def print_tld_count
        registry = Configuration.new.server_registry
        @stdout.puts "#{registry.size} TLDs supported"
        EXIT_OK
      end

      def check(domains)
        Checker.new(
          config: build_config,
          popular_tlds: @options[:popular_tlds],
          concurrency: @options[:concurrency]
        ).check_detailed(domains)
      end

      def build_config
        config = Configuration.new
        config.prefer = @options[:prefer]
        config.cache = @options[:cache]

        if @options[:timeout]
          timeout = @options[:timeout]
          config.socket_connect_timeout = timeout
          config.socket_read_timeout = timeout
          config.http_open_timeout = timeout
          config.http_read_timeout = timeout
        end

        config
      end

      def render(results)
        case @options[:format]
        when :json then render_json(results)
        else render_text(results)
        end
      end

      def render_json(results)
        payload = results.transform_values do |result|
          entry = result.to_h
          entry[:trace] = result.verdict&.trace if @options[:details]
          entry[:raw] = result.whois_message if @options[:raw]
          entry
        end

        @stdout.puts JSON.pretty_generate(payload)
      end

      def render_text(results)
        width = results.keys.map(&:length).max.to_i

        results.each do |name, result|
          @stdout.puts "#{name.ljust(width)}  #{colourise(result.status)}"
          next unless @options[:details]

          @stdout.puts "#{" " * width}  decided by: #{result.verdict&.rule || "-"}"
          @stdout.puts "#{" " * width}  reason:     #{result.reason}"
          @stdout.puts "#{" " * width}  endpoint:   #{result.response&.endpoint || "-"}"
          render_record(result, width)
        end

        render_raw(results) if @options[:raw]
      end

      def render_record(result, width)
        record = result.record
        return if record.nil? || record.empty?

        pad = " " * width
        @stdout.puts "#{pad}  registrar:  #{record.registrar}" if record.registrar
        @stdout.puts "#{pad}  created:    #{record.created_on&.iso8601}" if record.created_on
        @stdout.puts "#{pad}  expires:    #{record.expires_on&.iso8601}" if record.expires_on
        return if record.nameservers.empty?

        @stdout.puts "#{pad}  nameservers: #{record.nameservers.join(", ")}"
      end

      def render_raw(results)
        results.each do |name, result|
          @stdout.puts
          @stdout.puts "=== #{name} ==="
          @stdout.puts result.whois_message
        end
      end

      def colourise(status)
        return status.to_s unless colour?

        "#{COLOURS.fetch(status, "")}#{status}#{RESET}"
      end

      def colour?
        return @options[:colour] unless @options[:colour].nil?

        @stdout.respond_to?(:tty?) && @stdout.tty?
      end

      # Anything not conclusively answered is worth a non-zero exit, so a shell script
      # can tell "definitely free" from "could not find out".
      def exit_code(results)
        results.each_value.all?(&:conclusive?) ? EXIT_OK : EXIT_INCONCLUSIVE
      end

      def usage_error(message)
        @stderr.puts "monovm-whois: #{message}"
        @stderr.puts parser
        EXIT_USAGE
      end
    end
  end
end
