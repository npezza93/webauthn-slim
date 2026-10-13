# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::CBOR do
  # Independent RFC 8949 encodings, rather than just encoder/decoder round trips.
  {
    "00" => 0, "1818" => 24, "190100" => 256,
    "1a00010000" => 65536, "1b0000000100000000" => 4294967296,
    "20" => -1, "3863" => -100, "f4" => false, "f5" => true,
    "f6" => nil, "f7" => nil, "f93e00" => 1.5,
    "fa47c35000" => 100000.0, "fb3ff199999999999a" => 1.1,
    "83010203" => [1, 2, 3], "a26161016162820203" => { "a" => 1, "b" => [2, 3] },
    "9f01820203ff" => [1, [2, 3]], "bf616101616202ff" => { "a" => 1, "b" => 2 },
    "5f42010243030405ff" => "\x01\x02\x03\x04\x05".b,
    "7f657374726561646d696e67ff" => "streaming", "62c3bc" => "ü"
  }.each do |hex, expected|
    it "decodes #{hex}" do
      expect(described_class.decode([hex].pack("H*"))).to eq(expected)
    end
  end

  it "preserves the distinction between byte and text strings" do
    expect(described_class.decode("\x41a".b).encoding).to eq(Encoding::BINARY)
    expect(described_class.decode("\x61a".b).encoding).to eq(Encoding::UTF_8)
    expect(described_class.encode("a".b)).to eq("\x41a".b)
    expect(described_class.encode("a")).to eq("\x61a".b)
  end

  it "returns the exact consumed length for non-minimal encodings" do
    expect(described_class.decode_first("\x18\x01\x02".b)).to eq([1, 2])
  end

  it "encodes nested authenticator extension values" do
    value = { "example" => [true, false, nil, -100, 65536, 4294967296, "ü", "\xff".b, 1.5] }
    expect(described_class.decode(described_class.encode(value))).to eq(value)
  end

  ["", "18", "1c", "1f", "43aa", "62fffe", "8100ff", "9f00", "bf0102",
   "a201020103", "bf01020103ff", "5f6161ff", "7f4161ff", "5f5fff",
   "9bffffffffffffffff", "bbffffffffffffffff", "f8", "ff", "c001"].each do |hex|
    it "rejects malformed or unsupported input #{hex.inspect}" do
      expect { described_class.decode([hex].pack("H*")) }.to raise_error(described_class::MalformedData)
    end
  end

  it "bounds nesting depth" do
    expect { described_class.decode("\x81".b * 16 + "\x00".b) }.to raise_error(described_class::MalformedData)
  end

  it "bounds input size" do
    expect { described_class.decode("a" * (described_class::MAX_SIZE + 1)) }
      .to raise_error(described_class::MalformedData)
  end

  it "decodes half precision special values" do
    expect(described_class.decode(["f97c00"].pack("H*"))).to eq(Float::INFINITY)
    expect(described_class.decode(["f9fc00"].pack("H*"))).to eq(-Float::INFINITY)
    expect(described_class.decode(["f97e00"].pack("H*"))).to be_nan
    expect(described_class.decode(["f90001"].pack("H*"))).to eq(2.0**-24)
  end
end
