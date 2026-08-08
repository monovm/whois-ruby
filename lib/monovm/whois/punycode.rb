# frozen_string_literal: true

module MonoVM
  module Whois
    # Punycode (RFC 3492) encoder and decoder.
    #
    # Ruby has no Punycode or IDNA support in its standard library, and pulling in
    # a gem for ~120 lines of well-specified arithmetic would cost this library its
    # zero-dependency guarantee. So it lives here, transcribed from the reference
    # pseudocode in RFC 3492 section 6 and checked against the test vectors in
    # section 7.1.
    #
    # This module deals in single labels. Whole-name conversion, the +xn--+ prefix
    # and validation belong to {DomainName}.
    module Punycode
      BASE         = 36
      TMIN         = 1
      TMAX         = 26
      SKEW         = 38
      DAMP         = 700
      INITIAL_BIAS = 72
      INITIAL_N    = 128
      DELIMITER    = "-"

      # Highest code point that survives a round trip through the bias arithmetic
      # without overflowing what a DNS label could ever hold.
      MAX_CODE_POINT = 0x10FFFF

      # Raised when a label is not valid Punycode. Never leaks out of
      # {DomainName}, which treats an undecodable label as "leave it alone".
      class Error < MonoVM::Whois::Error; end

      class << self
        # Encode a Unicode label as Punycode, without the +xn--+ prefix.
        #
        #   Punycode.encode("münchen") # => "mnchen-3ya"
        #
        # @param input [String] one label, already normalised and downcased
        # @return [String]
        def encode(input)
          code_points = input.codepoints
          basic = code_points.select { |cp| basic?(cp) }

          output = basic.pack("U*")
          output += DELIMITER unless basic.empty?

          n = INITIAL_N
          delta = 0
          bias = INITIAL_BIAS
          handled = basic.length
          basic_length = basic.length

          while handled < code_points.length
            # The next code point to deal with is the smallest one we have not
            # reached yet; that ordering is what makes the encoding reversible.
            m = code_points.select { |cp| cp >= n }.min
            delta += (m - n) * (handled + 1)
            n = m

            code_points.each do |cp|
              delta += 1 if cp < n
              next unless cp == n

              output += encode_delta(delta, bias)
              bias = adapt(delta, handled + 1, handled == basic_length)
              delta = 0
              handled += 1
            end

            delta += 1
            n += 1
          end

          output
        end

        # Decode a Punycode label. The +xn--+ prefix must already be stripped.
        #
        #   Punycode.decode("mnchen-3ya") # => "münchen"
        #
        # @param input [String]
        # @return [String]
        # @raise [Error] if the input is not valid Punycode
        def decode(input)
          delimiter_at = input.rindex(DELIMITER)

          if delimiter_at
            basic = input[0...delimiter_at]
            raise Error, "non-basic code point before the delimiter" unless basic.ascii_only?

            output = basic.codepoints
            cursor = delimiter_at + 1
          else
            output = []
            cursor = 0
          end

          n = INITIAL_N
          i = 0
          bias = INITIAL_BIAS
          digits = input.codepoints

          while cursor < digits.length
            old_i = i
            weight = 1
            k = BASE

            loop do
              raise Error, "truncated punycode sequence" if cursor >= digits.length

              digit = digit_value(digits[cursor])
              cursor += 1

              i += digit * weight
              raise Error, "punycode overflow" if i > MAX_CODE_POINT * (output.length + 1)

              t = threshold(k, bias)
              break if digit < t

              weight *= (BASE - t)
              k += BASE
            end

            bias = adapt(i - old_i, output.length + 1, old_i.zero?)
            n += i / (output.length + 1)
            i %= (output.length + 1)

            raise Error, "punycode decoded to a basic code point" if basic?(n)
            raise Error, "punycode decoded outside Unicode" if n > MAX_CODE_POINT

            output.insert(i, n)
            i += 1
          end

          output.pack("U*")
        end

        private

        # Emit the variable-length integer for one delta, generalised
        # variable-length quantity style (RFC 3492 section 3.3).
        def encode_delta(delta, bias)
          out = +""
          q = delta
          k = BASE

          loop do
            t = threshold(k, bias)
            break if q < t

            out << digit_char(t + ((q - t) % (BASE - t)))
            q = (q - t) / (BASE - t)
            k += BASE
          end

          out << digit_char(q)
        end

        # t is k - bias clamped to [TMIN, TMAX].
        def threshold(k, bias)
          t = k - bias
          return TMIN if t < TMIN
          return TMAX if t > TMAX

          t
        end

        # Bias adaptation, RFC 3492 section 6.1. Keeps later deltas cheap to
        # encode by tracking how large the previous ones were.
        def adapt(delta, num_points, first_time)
          delta = first_time ? delta / DAMP : delta / 2
          delta += delta / num_points

          k = 0
          while delta > ((BASE - TMIN) * TMAX) / 2
            delta /= (BASE - TMIN)
            k += BASE
          end

          k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
        end

        def basic?(code_point)
          code_point < INITIAL_N
        end

        # 0..25 map to a..z, 26..35 to 0..9.
        def digit_char(digit)
          raise Error, "digit out of range: #{digit}" unless digit.between?(0, BASE - 1)

          (digit < 26 ? digit + 0x61 : digit - 26 + 0x30).chr
        end

        def digit_value(code_point)
          case code_point
          when 0x41..0x5A then code_point - 0x41       # A-Z
          when 0x61..0x7A then code_point - 0x61       # a-z
          when 0x30..0x39 then code_point - 0x30 + 26  # 0-9
          else
            raise Error, "not a punycode digit: #{code_point}"
          end
        end
      end
    end
  end
end
