# frozen_string_literal: true

require "webauthn/cbor"
require "webauthn/authenticator_data/attested_credential_data"
require "webauthn/error"

module WebAuthn
  class AuthenticatorDataFormatError < WebAuthn::Error; end

  class AuthenticatorData
    RP_ID_HASH_LENGTH = 32
    FLAGS_LENGTH = 1
    SIGN_COUNT_LENGTH = 4

    attr_reader :data, :rp_id_hash, :flags, :sign_count, :trailing_bytes

    def self.deserialize(data)
      new(data)
    end

    def initialize(data)
      unless data.is_a?(String) && data.bytesize >= base_length
        raise AuthenticatorDataFormatError
      end

      @data = data.b.freeze
      @rp_id_hash = @data.byteslice(0, RP_ID_HASH_LENGTH)
      @flags = @data.getbyte(RP_ID_HASH_LENGTH)
      @sign_count = @data.byteslice(RP_ID_HASH_LENGTH + FLAGS_LENGTH, SIGN_COUNT_LENGTH).unpack1("N")
      @trailing_bytes = @data.byteslice(base_length..-1)
    end

    def valid?
      (!attested_credential_data_included? || attested_credential_data.valid?) &&
        (!extension_data_included? || extension_data) &&
        valid_length?
    end

    def user_flagged?
      user_present? || user_verified?
    end

    def user_present?
      (flags & 0x1) != 0
    end

    def user_verified?
      (flags & 0x4) != 0
    end

    def credential_backup_eligible?
      (flags & 0x8) != 0
    end

    def credential_backed_up?
      (flags & 0x10) != 0
    end

    def attested_credential_data_included?
      (flags & 0x40) != 0
    end

    def extension_data_included?
      (flags & 0x80) != 0
    end

    def credential
      if attested_credential_data_included?
        attested_credential_data.credential
      end
    end

    def attested_credential_data
      @attested_credential_data ||=
        AttestedCredentialData.deserialize(trailing_bytes)
    rescue AttestedCredentialDataFormatError
      raise AuthenticatorDataFormatError
    end

    def extension_data
      @extension_data ||= CBOR.decode(raw_extension_data)
    rescue CBOR::MalformedData
      raise AuthenticatorDataFormatError
    end

    def aaguid
      raw_aaguid = attested_credential_data.raw_aaguid

      unless raw_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
        attested_credential_data.aaguid
      end
    end

    private

    def valid_length?
      data.bytesize == base_length + attested_credential_data_length + extension_data_length
    end

    def raw_extension_data
      if extension_data_included?
        if attested_credential_data_included?
          trailing_bytes[attested_credential_data.length..-1]
        else
          trailing_bytes
        end
      end
    end

    def attested_credential_data_length
      if attested_credential_data_included?
        attested_credential_data.length
      else
        0
      end
    end

    def extension_data_length
      if extension_data_included?
        raw_extension_data.length
      else
        0
      end
    end

    def base_length
      RP_ID_HASH_LENGTH + FLAGS_LENGTH + SIGN_COUNT_LENGTH
    end
  end
end
