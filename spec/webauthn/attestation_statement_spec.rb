# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::AttestationStatement do
  ["android-key", "android-safetynet", "tpm"].each do |format|
    it "rejects #{format} attestation even when attestation verification is disabled" do
      relying_party = WebAuthn::RelyingParty.new(verify_attestation_statement: false)
      encoded = WebAuthn::FakeAuthenticator.new.make_credential(rp_id: "localhost", client_data_hash: "\x00".b * 32)
      map = WebAuthn::CBOR.decode(encoded)
      map["fmt"] = format

      expect { WebAuthn::AttestationObject.deserialize(WebAuthn::CBOR.encode(map), relying_party) }
        .to raise_error(described_class::FormatNotSupportedError, "Unsupported attestation format '#{format}'")
    end
  end
end
