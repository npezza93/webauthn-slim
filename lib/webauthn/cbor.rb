# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  # The WebAuthn subset of RFC 8949, without a native extension. Inspired by
  # the bounded decoder in https://github.com/rails/rails/pull/57100.
  module CBOR
    class MalformedData < WebAuthn::Error; end

    MAX_SIZE = 10 * 1024 * 1024
    MAX_DEPTH = 16

    def self.decode(data)
      decoder = Decoder.new(data)
      value = decoder.decode
      raise MalformedData, "Trailing CBOR data" unless decoder.position == data.bytesize

      value
    end

    # Returns both the first item and its exact encoded length. Credential keys
    # can be followed by extensions, and need not use the shortest encoding.
    def self.decode_first(data)
      decoder = Decoder.new(data)
      [decoder.decode, decoder.position]
    end

    def self.encode(value)
      case value
      when Integer
        value >= 0 ? header(0, value) : header(1, -1 - value)
      when String
        header(value.encoding == Encoding::BINARY ? 2 : 3, value.bytesize) + value.b
      when Array
        header(4, value.length) + value.map { |item| encode(item) }.join
      when Hash
        header(5, value.length) + value.map { |key, item| encode(key) + encode(item) }.join
      when false then "\xf4".b
      when true then "\xf5".b
      when nil then "\xf6".b
      when Float then "\xfb".b + [value].pack("G")
      else raise ArgumentError, "Unsupported CBOR value #{value.class}"
      end
    end

    def self.header(type, value)
      prefix = type << 5
      case value
      when 0..23 then [prefix | value].pack("C")
      when 24..255 then [prefix | 24, value].pack("CC")
      when 256..65535 then [prefix | 25, value].pack("Cn")
      when 65536..0xffffffff then [prefix | 26, value].pack("CN")
      when 0x100000000..0xffffffffffffffff then [prefix | 27, value].pack("CQ>")
      else raise ArgumentError, "CBOR integer out of range"
      end
    end
    private_class_method :header

    class Decoder
      attr_reader :position

      def initialize(data)
        raise MalformedData, "Expected CBOR bytes" unless data.is_a?(String)
        raise MalformedData, "Input exceeds maximum size" if data.bytesize > MAX_SIZE

        @data = data.b
        @position = 0
      end

      def decode(depth = 0)
        raise MalformedData, "Maximum nesting depth exceeded" if depth >= MAX_DEPTH

        byte = read(1).getbyte(0)
        type = byte >> 5
        info = byte & 31
        return simple(info) if type == 7

        if info == 31
          return indefinite(type, depth)
        end

        size = argument(info)
        case type
        when 0 then size
        when 1 then -1 - size
        when 2, 3 then string(type, read(size))
        when 4
          raise MalformedData, "Truncated CBOR array" if size > remaining

          Array.new(size) { decode(depth + 1) }
        when 5
          raise MalformedData, "Truncated CBOR map" if size > remaining / 2

          {}.tap { |map| size.times { read_pair(map, depth) } }
        else raise MalformedData, "Unsupported CBOR tag #{size}"
        end
      end

      private

      def read(size)
        raise MalformedData, "Unexpected end of input" if size > remaining

        bytes = @data.byteslice(@position, size)
        @position += size
        bytes
      end

      def remaining
        @data.bytesize - position
      end

      def argument(info)
        case info
        when 0..23 then info
        when 24 then read(1).unpack1("C")
        when 25 then read(2).unpack1("n")
        when 26 then read(4).unpack1("N")
        when 27 then read(8).unpack1("Q>")
        else raise MalformedData, "Invalid CBOR additional information"
        end
      end

      def string(type, bytes)
        return bytes if type == 2

        bytes.force_encoding(Encoding::UTF_8)
        raise MalformedData, "Invalid CBOR UTF-8 string" unless bytes.valid_encoding?

        bytes
      end

      def read_pair(map, depth)
        key = decode(depth + 1)
        raise MalformedData, "Duplicate CBOR map key" if map.key?(key)

        map[key] = decode(depth + 1)
      end

      def indefinite(type, depth)
        raise MalformedData, "Invalid indefinite CBOR item" unless (2..5).include?(type)

        value = type == 5 ? {} : (type == 4 ? [] : "".b)
        until @data.getbyte(position) == 255
          if type == 5
            read_pair(value, depth)
          elsif type == 4
            value << decode(depth + 1)
          else
            byte = @data.getbyte(position)
            unless byte && byte >> 5 == type && byte & 31 != 31
              raise MalformedData, "Invalid indefinite string chunk"
            end

            value << decode(depth + 1)
          end
        end
        read(1)
        type == 3 ? string(type, value) : value
      end

      def simple(info)
        case info
        when 20 then false
        when 21 then true
        when 22, 23 then nil
        when 25
          half = read(2).unpack1("n")
          exponent = (half >> 10) & 31
          mantissa = half & 1023
          value =
            if exponent == 0
              Math.ldexp(mantissa, -24)
            elsif exponent == 31
              mantissa == 0 ? Float::INFINITY : Float::NAN
            else
              Math.ldexp(mantissa + 1024, exponent - 25)
            end
          half & 0x8000 == 0 ? value : -value
        when 26 then read(4).unpack1("g")
        when 27 then read(8).unpack1("G")
        else raise MalformedData, "Unsupported CBOR simple value"
        end
      end
    end
    private_constant :Decoder
  end
end
