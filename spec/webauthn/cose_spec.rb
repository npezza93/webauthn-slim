# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::COSE do
  let(:data) { "signed authenticator data" }

  [
    ["ES256", "prime256v1"], ["ES384", "secp384r1"],
    ["ES512", "secp521r1"], ["ES256K", "secp256k1"],
    ["RS256", nil], ["RS384", nil], ["RS512", nil], ["RS1", nil],
    ["PS256", nil], ["PS384", nil], ["PS512", nil],
    ["EdDSA", "ED25519"], ["EdDSA", "ED448"]
  ].each do |name, curve|
    context "with #{name} #{curve}" do
      let(:algorithm) { described_class::Algorithm.by_name(name) }
      let(:key) do
        if name.start_with?("ES")
          OpenSSL::PKey::EC.generate(curve)
        elsif name == "EdDSA"
          OpenSSL::PKey.generate_key(curve)
        else
          create_rsa_key(2048)
        end
      end
      let(:cose_key) do
        key_class =
          if name.start_with?("ES")
            described_class::Key::EC2
          elsif name == "EdDSA"
            described_class::Key::OKP
          else
            described_class::Key::RSA
          end
        key_class.from_pkey(key).tap { |cose| cose.alg = algorithm.id }
      end
      let(:public_key) { WebAuthn::PublicKey.deserialize(cose_key.serialize) }
      let(:signature) do
        if name.start_with?("PS")
          key.sign_pss(algorithm.hash_function, data, salt_length: :digest, mgf1_hash: algorithm.hash_function)
        else
          key.sign(algorithm.hash_function, data)
        end
      end

      it "builds the original public key and verifies its signature" do
        expect(public_key.pkey.public_to_der).to eq(key.public_to_der)
        expect(public_key.verify(signature, data)).to be_truthy
        expect(public_key.verify(signature, data + "changed")).to be_falsy
      end
    end
  end

  it "rejects EC algorithm and curve mismatches" do
    key = described_class::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate("secp384r1"))
    key.alg = -7
    expect(WebAuthn::PublicKey.deserialize(key.serialize).verify("signature", data)).to be_falsy
  end

  it "rejects algorithm and key type mismatches" do
    key = described_class::Key::RSA.from_pkey(create_rsa_key)
    key.alg = -7
    expect(WebAuthn::PublicKey.deserialize(key.serialize).verify("signature", data)).to be_falsy
  end

  it "requires a PSS salt length equal to the digest length" do
    key = create_rsa_key(2048)
    signature = key.sign_pss("SHA256", data, salt_length: 0, mgf1_hash: "SHA256")
    expect(described_class::Algorithm.find(-37).verify(key, signature, data)).to be_falsy
  end

  [
    { 1 => 2, 3 => -7, -1 => 1, -2 => "x".b * 31, -3 => "y".b * 32 },
    { 1 => 2, 3 => -7, -1 => 999, -2 => "x".b * 32, -3 => "y".b * 32 },
    { 1 => 2, 3 => -7, -1 => 1, -2 => "x" * 32, -3 => "y" * 32 },
    { 1 => 1, 3 => -8, -1 => 6, -2 => "x".b * 31 },
    { 1 => 3, 3 => -257, -1 => "".b, -2 => "\x03".b },
    { 1 => 3, 3 => "RS256", -1 => "\x01".b, -2 => "\x03".b }
  ].each_with_index do |map, index|
    it "rejects malformed key parameters #{index}" do
      expect { described_class::Key.deserialize(WebAuthn::CBOR.encode(map)) }
        .to raise_error(described_class::MalformedKeyError)
    end
  end
end
