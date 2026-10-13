# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::AuthenticatorData do
  let(:serialized_authenticator_data) do
    WebAuthn::FakeAuthenticator::AuthenticatorData.new(
      rp_id_hash: rp_id_hash,
      sign_count: sign_count,
      user_present: user_present,
      user_verified: user_verified,
      backup_eligibility: backup_eligibility,
      backup_state: backup_state,
    ).serialize
  end

  let(:rp_id_hash) { OpenSSL::Digest.digest("SHA256", "localhost") }
  let(:sign_count) { 42 }
  let(:user_present) { true }
  let(:user_verified) { false }
  let(:backup_eligibility) { false }
  let(:backup_state) { false }

  let(:authenticator_data) { described_class.deserialize(serialized_authenticator_data) }

  describe ".deserialize" do
    it "rejects every truncated fixed header" do
      (0...37).each do |length|
        expect { described_class.deserialize(serialized_authenticator_data.byteslice(0, length)) }
          .to raise_error(WebAuthn::AuthenticatorDataFormatError)
      end
    end

    it "keeps non-minimal key encodings separate from extension data" do
      key = fake_cose_credential_key
      # Encode the map size using an extra byte, a valid but non-minimal CBOR encoding.
      key = "\xb8\x05".b + key.byteslice(1..-1)
      extensions = { "example" => true }
      data = rp_id_hash + [0xc1, 42].pack("CN") + "\x00".b * 16 + [2].pack("n") +
             "id" + key + WebAuthn::CBOR.encode(extensions)
      parsed = described_class.deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.credential.public_key).to eq(key)
      expect(parsed.extension_data).to eq(extensions)
      expect(parsed.data).to eq(data)
    end

    it "rejects trailing bytes after the extension map" do
      expect { described_class.deserialize(serialized_authenticator_data + "\x00".b).valid? }
        .to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end
  end

  describe "#valid?" do
    it "returns true" do
      expect(authenticator_data.valid?).to be_truthy
    end

    it "returns false if leftover bytes" do
      data = WebAuthn::FakeAuthenticator::AuthenticatorData.new(
        rp_id_hash: rp_id_hash,
        sign_count: sign_count,
        user_present: user_present,
        user_verified: user_verified,
        extensions: nil
      ).serialize

      authenticator_data = WebAuthn::AuthenticatorData.deserialize(data + WebAuthn::CBOR.encode("k" => "v"))

      expect(authenticator_data.valid?).to be_falsy
    end
  end

  describe "#rp_id_hash" do
    subject { authenticator_data.rp_id_hash }

    it { is_expected.to eq(rp_id_hash) }
  end

  describe "#sign_count" do
    subject { authenticator_data.sign_count }

    it { is_expected.to eq(42) }
  end

  describe "#user_present?" do
    subject { authenticator_data.user_present? }

    context "when UP flag is set" do
      let(:user_present) { true }

      it { is_expected.to be_truthy }
    end

    context "when UP flag is not set" do
      let(:user_present) { false }

      it { is_expected.to be_falsy }
    end
  end

  describe "#user_verified?" do
    subject { authenticator_data.user_verified? }

    context "when UV flag is set" do
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when UV flag is not set" do
      let(:user_verified) { false }

      it { is_expected.to be_falsy }
    end
  end

  describe "#user_flagged?" do
    subject { authenticator_data.user_flagged? }

    context "when both UP and UV flag are set" do
      let(:user_present) { true }
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when only UP is set" do
      let(:user_present) { true }
      let(:user_verified) { false }

      it { is_expected.to be_truthy }
    end

    context "when only UV flag is set" do
      let(:user_present) { false }
      let(:user_verified) { true }

      it { is_expected.to be_truthy }
    end

    context "when both UP and UV flag are not set" do
      let(:user_present) { false }
      let(:user_verified) { false }

      it { is_expected.to be_falsy }
    end
  end

  describe "#credential_backup_eligible?" do
    subject { authenticator_data.credential_backup_eligible? }

    context "when BE flag is set" do
      let(:backup_eligibility) { true }

      it { is_expected.to be_truthy }
    end

    context "when BE flag is not set" do
      let(:backup_eligibility) { false }

      it { is_expected.to be_falsy }
    end
  end

  describe "#credential_backed_up?" do
    subject { authenticator_data.credential_backed_up? }

    context "when BS flag is set" do
      let(:backup_state) { true }

      it { is_expected.to be_truthy }
    end

    context "when BS flag is not set" do
      let(:backup_state) { false }

      it { is_expected.to be_falsy }
    end
  end
end
