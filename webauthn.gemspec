# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "webauthn/version"

Gem::Specification.new do |spec|
  spec.name          = "webauthn-slim"
  spec.version       = WebAuthn::VERSION
  spec.authors       = ["Gonzalo Rodriguez", "Braulio Martinez"]
  spec.email         = ["gonzalo@cedarcode.com", "braulio@cedarcode.com"]

  spec.summary       = "WebAuthn ruby server library"
  spec.description   = 'WebAuthn ruby server library ― Make your application a W3C Web Authentication conformant'
  spec.homepage      = "https://github.com/npezza93/webauthn-slim"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/npezza93/webauthn-slim/issues",
    "changelog_uri" => "https://github.com/npezza93/webauthn-slim/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/npezza93/webauthn-slim"
  }

  spec.files =
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features|assets)/})
    end

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 4.0"

  spec.add_dependency "openssl", ">= 2.2"

  spec.add_development_dependency "bundler", "~> 4.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.8"
  spec.add_development_dependency "rubocop", "~> 1"
  spec.add_development_dependency "rubocop-rake", "~> 0.5"
  spec.add_development_dependency "rubocop-rspec", ">= 2.2", "< 4.0"
end
