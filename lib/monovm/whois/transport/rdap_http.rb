# frozen_string_literal: true

require "net/http"
require "openssl"
require "uri"
require_relative "base"
require_relative "../version"

module MonoVM
  module Whois
    module Transport
      # RDAP over HTTPS (RFC 7480-7483).
      #
      # RDAP is the reason this library can be confident where a WHOIS-only one has
      # to guess. A registered domain comes back as JSON with an +objectClassName+;
      # an unregistered one comes back as HTTP 404 with an +errorCode+ of 404. Both
      # are answers, so both are returned as a {Response} for the rules to read.
      #
      # What is *not* an answer gets raised instead: 401/403/405/406/429 mean the
      # server refused us, and 5xx means it broke. Handing those bodies back would
      # let an error page be pattern-matched into "available".
      class RdapHttp < Base
        DEFAULT_OPEN_TIMEOUT = 10.0
        DEFAULT_READ_TIMEOUT = 30.0
        MAX_REDIRECTS = 3

        # 404 carries the "no such domain" answer, so it is deliberately absent.
        REFUSAL_STATUSES = [401, 403, 405, 406, 429].freeze

        ACCEPT = "application/rdap+json, application/json;q=0.9, */*;q=0.1"

        attr_reader :open_timeout, :read_timeout, :verify_ssl, :user_agent

        # @param verify_ssl [Boolean] verify TLS certificates. Defaults to true.
        #   A handful of registry endpoints do serve broken chains; those
        #   deployments can opt out explicitly rather than everyone losing the
        #   guarantee silently.
        def initialize(open_timeout: DEFAULT_OPEN_TIMEOUT, read_timeout: DEFAULT_READ_TIMEOUT,
                       verify_ssl: true, user_agent: nil)
          @open_timeout = open_timeout
          @read_timeout = read_timeout
          @verify_ssl = verify_ssl
          @user_agent = user_agent || "monovm-whois/#{MonoVM::Whois::VERSION} (+https://github.com/monovm/whois-ruby)"
          super()
        end

        def supports?(endpoint)
          endpoint.http?
        end

        # @return [Response]
        # @raise [ConnectionError, TimeoutError, ServerRefusedError, EmptyResponseError]
        def fetch(query:, endpoint:)
          url = URI.parse(endpoint.url_for(query))
          (response, elapsed) = measure { request(url, endpoint) }

          Response.new(
            body: response.body.to_s,
            endpoint: endpoint,
            query: query,
            status: Integer(response.code),
            elapsed: elapsed
          )
        rescue URI::InvalidURIError => e
          raise ConnectionError, "cannot build an RDAP URL for #{query}: #{e.message}"
        end

        private

        def request(url, endpoint, redirects_left = MAX_REDIRECTS)
          response = perform(url, endpoint)

          # RDAP registries do redirect: a registry may hand a name off to the
          # registrar's own server, and the answer is at the new location.
          if redirect?(response) && redirects_left.positive?
            location = response["location"]
            return request(URI.join(url, location), endpoint, redirects_left - 1) if location
          end

          verify_answerable!(response, endpoint)
          response
        end

        def perform(url, endpoint)
          http = build_http(url)
          request = Net::HTTP::Get.new(url)
          request["Accept"] = ACCEPT
          request["User-Agent"] = user_agent

          http.start { |connection| connection.request(request) }
        rescue Net::OpenTimeout, Net::ReadTimeout => e
          raise TimeoutError, "#{endpoint.host} timed out after #{timeout_for(e)}s (#{e.class})"
        rescue OpenSSL::SSL::SSLError => e
          raise ConnectionError, "TLS handshake with #{endpoint.host} failed: #{e.message}"
        rescue SocketError, SystemCallError, Net::HTTPBadResponse, Net::ProtocolError, IOError => e
          raise ConnectionError, "cannot reach #{endpoint.host}: #{e.message}"
        end

        def build_http(url)
          http = Net::HTTP.new(url.host, url.port)
          http.use_ssl = url.scheme == "https"
          http.open_timeout = open_timeout
          http.read_timeout = read_timeout

          http.verify_mode = OpenSSL::SSL::VERIFY_NONE unless verify_ssl

          http
        end

        def redirect?(response)
          response.is_a?(Net::HTTPRedirection)
        end

        # Separate "the server answered the question" from "the server declined".
        def verify_answerable!(response, endpoint)
          status = Integer(response.code)

          if REFUSAL_STATUSES.include?(status)
            raise ServerRefusedError.new(
              "#{endpoint.host} refused the query with HTTP #{status} #{response.message}",
              endpoint: endpoint
            )
          end

          if status >= 500
            raise ServerRefusedError.new(
              "#{endpoint.host} failed with HTTP #{status} #{response.message}",
              endpoint: endpoint
            )
          end

          # A 404 with no body is still an answer in RDAP terms, but an empty 200 is
          # not: there is nothing in it to classify either way.
          return unless status == 200 && response.body.to_s.strip.empty?

          raise EmptyResponseError, "#{endpoint.host} returned an empty 200 for the query"
        end

        def timeout_for(error)
          error.is_a?(Net::OpenTimeout) ? open_timeout : read_timeout
        end
      end
    end
  end
end
