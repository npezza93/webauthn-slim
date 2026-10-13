# frozen_string_literal: true

require "webauthn/cbor"
require "webauthn/cose"
require "webauthn/error"

module WebAuthn
  class AttestedCredentialDataFormatError < WebAuthn::Error; end

  class AuthenticatorData
    class AttestedCredentialData
      AAGUID_LENGTH = 16
      ZEROED_AAGUID = 0.chr * AAGUID_LENGTH

      ID_LENGTH_LENGTH = 2

      attr_reader :raw_aaguid, :id_length, :id, :trailing_bytes

      Credential =
        Struct.new(:id, :public_key, :algorithm, keyword_init: true) do
          def public_key_object
            COSE::Key.deserialize(public_key).to_pkey
          end
        end

      def self.deserialize(data)
        new(data)
      end

      def initialize(data)
        header_length = AAGUID_LENGTH + ID_LENGTH_LENGTH
        unless data.is_a?(String) && data.bytesize >= header_length
          raise AttestedCredentialDataFormatError
        end

        data = data.b
        @raw_aaguid = data.byteslice(0, AAGUID_LENGTH)
        @id_length = data.byteslice(AAGUID_LENGTH, ID_LENGTH_LENGTH).unpack1("n")
        if data.bytesize < header_length + id_length
          raise AttestedCredentialDataFormatError
        end

        @id = data.byteslice(header_length, id_length)
        @trailing_bytes = data.byteslice(header_length + id_length..-1)
      end

      def valid?
        valid_credential_public_key?
      end

      def aaguid
        raw_aaguid.unpack("H8H4H4H4H12").join("-")
      end

      def credential
        @credential ||=
          if valid?
            Credential.new(id: id, public_key: public_key, algorithm: algorithm)
          end
      end

      def length
        if valid?
          AAGUID_LENGTH + ID_LENGTH_LENGTH + id_length + public_key_length
        end
      end

      private

      def algorithm
        COSE::Algorithm.find(cose_key.alg)&.name
      end

      def valid_credential_public_key?
        !!cose_key.alg
      end

      def cose_key
        @cose_key ||= COSE::Key.deserialize(public_key)
      end

      def public_key
        trailing_bytes[0..public_key_length - 1]
      end

      def public_key_length
        @public_key_length ||=
          CBOR.decode_first(trailing_bytes).last
      rescue CBOR::MalformedData
        raise AttestedCredentialDataFormatError
      end
    end
  end
end
