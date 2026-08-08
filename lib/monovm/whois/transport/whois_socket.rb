# frozen_string_literal: true

require "socket"
require_relative "base"

module MonoVM
  module Whois
    module Transport
      # WHOIS over TCP port 43 (RFC 3912).
      #
      # The protocol is as thin as protocols get: connect, send the query and a
      # CRLF, read until the server closes. What needs care is everything around
      # that — a registry that accepts the connection and then never answers, one
      # that sends half a record and hangs up, one that replies in Latin-1.
      class WhoisSocket < Base
        DEFAULT_CONNECT_TIMEOUT = 10.0
        DEFAULT_READ_TIMEOUT = 15.0
        CHUNK_SIZE = 16_384

        # Registries that answer in Latin-1. Trying UTF-8 first and falling back
        # keeps accented registrant names readable rather than replacing them with
        # U+FFFD.
        FALLBACK_ENCODING = Encoding::ISO_8859_1

        # IO::TimeoutError only exists from Ruby 3.2. Naming it directly in a rescue
        # clause would raise NameError on 3.1 at the moment an exception occurred —
        # turning a timeout into a crash — so the list is built once, here.
        CONNECT_TIMEOUTS = [
          Errno::ETIMEDOUT,
          (IO::TimeoutError if defined?(IO::TimeoutError))
        ].compact.freeze

        attr_reader :connect_timeout, :read_timeout

        def initialize(connect_timeout: DEFAULT_CONNECT_TIMEOUT, read_timeout: DEFAULT_READ_TIMEOUT)
          @connect_timeout = connect_timeout
          @read_timeout = read_timeout
          super()
        end

        def supports?(endpoint)
          endpoint.socket?
        end

        # @return [Response]
        # @raise [ConnectionError, TimeoutError, EmptyResponseError]
        def fetch(query:, endpoint:)
          body, elapsed = measure { exchange(query, endpoint) }

          if body.strip.empty?
            raise EmptyResponseError,
                  "#{endpoint.host} closed the connection without answering for #{query}"
          end

          Response.new(body: body, endpoint: endpoint, query: query, elapsed: elapsed)
        end

        private

        def exchange(query, endpoint)
          socket = connect(endpoint)

          begin
            socket.write("#{query}\r\n")
            read_all(socket, endpoint)
          ensure
            begin
              socket.close
            rescue IOError, SystemCallError
              # Already closed by the peer; nothing to salvage.
            end
          end
        end

        def connect(endpoint)
          Socket.tcp(endpoint.host, endpoint.port, connect_timeout: connect_timeout)
        rescue *CONNECT_TIMEOUTS => e
          raise TimeoutError, "timed out connecting to #{endpoint.host}:#{endpoint.port} (#{e.class})"
        rescue SocketError, SystemCallError => e
          raise ConnectionError, "cannot reach #{endpoint.host}:#{endpoint.port}: #{e.message}"
        end

        # Read until the peer closes, bounded by a single deadline for the whole
        # response rather than per chunk — a server that dribbles one byte per
        # second should not be able to hold the caller indefinitely.
        def read_all(socket, endpoint)
          deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + read_timeout
          chunks = []

          loop do
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            return partial(chunks, endpoint, "read timed out", TimeoutError) if remaining <= 0

            unless socket.wait_readable(remaining)
              return partial(chunks, endpoint, "read timed out",
                             TimeoutError)
            end

            begin
              chunks << socket.readpartial(CHUNK_SIZE)
            rescue EOFError
              break
            rescue SystemCallError => e
              return partial(chunks, endpoint, e.message, ConnectionError)
            end
          end

          decode(chunks.join)
        end

        # A truncated record still classifies correctly far more often than not, so
        # whatever arrived is kept. Nothing at all is a failure, not a verdict.
        def partial(chunks, endpoint, reason, error_class)
          raise error_class, "#{endpoint.host}:#{endpoint.port} #{reason}" if chunks.empty?

          decode(chunks.join)
        end

        def decode(raw)
          text = raw.dup.force_encoding(Encoding::UTF_8)
          return text if text.valid_encoding?

          raw.dup.force_encoding(FALLBACK_ENCODING).encode(Encoding::UTF_8)
        rescue EncodingError
          raw.dup.force_encoding(Encoding::UTF_8).scrub("")
        end
      end
    end
  end
end
