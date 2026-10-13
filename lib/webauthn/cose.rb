# frozen_string_literal: true

require "openssl"
require "webauthn/cbor"

module WebAuthn
  # Public COSE keys and signature algorithms used by WebAuthn (RFC 9053).
  # SubjectPublicKeyInfo construction follows the approach in Rails PR #57100.
  module COSE
    class Error < WebAuthn::Error; end
    class MalformedKeyError < Error; end
    class UnknownKeyType < Error; end

    module Key
      Curve =
        Struct.new(:id, :name, :pkey_name, :coordinate_length) do
          def self.find(id)
            CURVES.find { |curve| curve.id == id }
          end

          def self.by_name(name)
            CURVES.find { |curve| curve.name == name }
          end

          def self.by_pkey_name(name)
            CURVES.find { |curve| curve.pkey_name == name }
          end
        end

      CURVES = [
        Curve.new(1, "P-256", "prime256v1", 32),
        Curve.new(2, "P-384", "secp384r1", 48),
        Curve.new(3, "P-521", "secp521r1", 66),
        Curve.new(6, "Ed25519", "ED25519", 32),
        Curve.new(7, "Ed448", "ED448", 57),
        Curve.new(8, "secp256k1", "secp256k1", 32)
      ].each(&:freeze).freeze

      def self.deserialize(bytes)
        map = CBOR.decode(bytes)
        type = map.is_a?(Hash) && map[1]
        case type
        when 1 then OKP.new(alg: map[3], crv: map[-1], x: map[-2])
        when 2 then EC2.new(alg: map[3], crv: map[-1], x: map[-2], y: map[-3])
        when 3 then RSA.new(alg: map[3], n: map[-1], e: map[-2])
        else raise UnknownKeyType, "Unsupported COSE key type #{type}"
        end
      rescue CBOR::MalformedData, ArgumentError => e
        raise MalformedKeyError, e.message
      end

      class Base
        attr_accessor :alg

        def self.deserialize(bytes)
          key = Key.deserialize(bytes)
          raise MalformedKeyError, "Unexpected COSE key type" unless key.is_a?(self)

          key
        end

        def initialize(alg: nil)
          raise ArgumentError, "Invalid COSE algorithm" unless alg.nil? || alg.is_a?(Integer)

          @alg = alg
        end

        def serialize
          CBOR.encode(map)
        end

        private

        def bytes?(value, length = nil)
          value.is_a?(String) && value.encoding == Encoding::BINARY &&
            (length ? value.bytesize == length : !value.empty?)
        end

        def subject_public_key(identifiers, bytes)
          OpenSSL::PKey.read(
            OpenSSL::ASN1::Sequence(
              [
                OpenSSL::ASN1::Sequence(identifiers.map { |name| OpenSSL::ASN1::ObjectId(name) }),
                OpenSSL::ASN1::BitString(bytes)
              ]
            ).to_der
          )
        end
      end

      class EC2 < Base
        attr_reader :crv, :x, :y

        def self.from_pkey(key)
          curve = Curve.by_pkey_name(key.group.curve_name)
          raise ArgumentError, "Unsupported EC curve" unless curve

          point = key.is_a?(OpenSSL::PKey::EC) ? key.public_key : key
          bytes = point.to_octet_string(:uncompressed)
          size = curve.coordinate_length
          new(crv: curve.id, x: bytes.byteslice(1, size), y: bytes.byteslice(1 + size, size))
        end

        def initialize(crv:, x:, y:, **options) # rubocop:disable Naming/MethodParameterName
          super(**options)
          @crv, @x, @y = crv, x, y
          curve = Curve.find(crv)
          unless [1, 2, 3, 8].include?(crv) && bytes?(x, curve.coordinate_length) && bytes?(y, curve.coordinate_length)
            raise ArgumentError, "Invalid EC2 curve or coordinates"
          end
        end

        def map
          { 1 => 2, 3 => alg, -1 => crv, -2 => x, -3 => y }.compact
        end

        def to_pkey
          subject_public_key(["id-ecPublicKey", Curve.find(crv).pkey_name], "\x04".b + x + y)
        end
      end

      class OKP < Base
        attr_reader :crv, :x

        def self.from_pkey(key)
          curve = Curve.by_pkey_name(key.oid)
          raise ArgumentError, "Unsupported OKP curve" unless curve

          new(crv: curve.id, x: OpenSSL::ASN1.decode(key.public_to_der).value.last.value)
        end

        def initialize(crv:, x:, **options) # rubocop:disable Naming/MethodParameterName
          super(**options)
          @crv, @x = crv, x
          unless [6, 7].include?(crv) && bytes?(x, Curve.find(crv).coordinate_length)
            raise ArgumentError, "Invalid OKP curve or public key"
          end
        end

        def map
          { 1 => 1, 3 => alg, -1 => crv, -2 => x }.compact
        end

        def to_pkey
          subject_public_key([Curve.find(crv).pkey_name], x)
        end
      end

      class RSA < Base
        attr_reader :n, :e

        def self.from_pkey(key)
          new(n: key.n.to_s(2), e: key.e.to_s(2))
        end

        def initialize(n:, e:, **options) # rubocop:disable Naming/MethodParameterName
          super(**options)
          raise ArgumentError, "Invalid RSA modulus or exponent" unless bytes?(n) && bytes?(e)

          @n, @e = n, e
        end

        def map
          { 1 => 3, 3 => alg, -1 => n, -2 => e }.compact
        end

        def to_pkey
          OpenSSL::PKey::RSA.new(
            OpenSSL::ASN1::Sequence([n, e].map { |bytes| OpenSSL::ASN1::Integer(OpenSSL::BN.new(bytes, 2)) }).to_der
          )
        end
      end
    end

    Algorithm =
      Struct.new(:id, :name, :hash_function, :key_type, :curve_name) do
        def self.find(id_or_name)
          ALGORITHMS.find { |algorithm| algorithm.id == id_or_name || algorithm.name == id_or_name }
        end

        def self.by_name(name)
          find(name)
        end

        def compatible_key?(key)
          case key_type
          when :ec
            key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == curve_name
          when :rsa
            key.is_a?(OpenSSL::PKey::RSA)
          when :eddsa
            key.respond_to?(:oid) && ["ED25519", "ED448"].include?(key.oid)
          end
        end

        def verify(key, signature, data)
          return false unless compatible_key?(key)

          if name.start_with?("PS")
            key.verify_pss(hash_function, signature, data, salt_length: :digest, mgf1_hash: hash_function)
          else
            if key_type == :ec
              size = (key.group.degree + 7) / 8
              if signature.bytesize == size * 2
                signature = OpenSSL::ASN1::Sequence(
                  [signature.byteslice(0, size), signature.byteslice(size, size)].map do |bytes|
                    OpenSSL::ASN1::Integer(OpenSSL::BN.new(bytes, 2))
                  end
                ).to_der
              end
            end

            key.verify(hash_function, signature, data)
          end
        rescue OpenSSL::PKey::PKeyError
          raise unless key_type == :eddsa

          false
        end
      end

    ALGORITHMS = [
      Algorithm.new(-7, "ES256", "SHA256", :ec, "prime256v1"),
      Algorithm.new(-35, "ES384", "SHA384", :ec, "secp384r1"),
      Algorithm.new(-36, "ES512", "SHA512", :ec, "secp521r1"),
      Algorithm.new(-47, "ES256K", "SHA256", :ec, "secp256k1"),
      Algorithm.new(-8, "EdDSA", nil, :eddsa),
      Algorithm.new(-37, "PS256", "SHA256", :rsa),
      Algorithm.new(-38, "PS384", "SHA384", :rsa),
      Algorithm.new(-39, "PS512", "SHA512", :rsa),
      Algorithm.new(-257, "RS256", "SHA256", :rsa),
      Algorithm.new(-258, "RS384", "SHA384", :rsa),
      Algorithm.new(-259, "RS512", "SHA512", :rsa),
      Algorithm.new(-65535, "RS1", "SHA1", :rsa)
    ].each(&:freeze).freeze
  end
end
