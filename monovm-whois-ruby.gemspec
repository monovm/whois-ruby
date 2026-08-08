# frozen_string_literal: true

require_relative "lib/monovm/whois/version"

Gem::Specification.new do |spec|
  spec.name     = "monovm-whois-ruby"
  spec.version  = MonoVM::Whois::VERSION
  spec.authors  = ["MonoVM"]
  spec.email    = ["dev@monovm.com"]

  spec.summary  = "Domain WHOIS and RDAP lookups with reliable availability detection."
  spec.description = <<~TEXT
    Look up domain registration data and check availability over RDAP and WHOIS
    (port 43). Prefers RDAP where a registry offers it, falls back to port 43,
    follows registrar referrals for thin registries, and parses records into
    structured objects. Availability detection is a priority-ordered rule chain
    that reports "unknown" instead of guessing when a server refuses to answer.
    No runtime dependencies.
  TEXT

  spec.homepage = "https://github.com/monovm/whois-ruby"
  spec.license  = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.metadata = {
    # No source_code_uri: it would be the same URL as homepage_uri, and RubyGems warns
    # about that rather than showing both.
    "homepage_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "documentation_uri" => "https://rubydoc.info/gems/monovm-whois-ruby",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir[
    "lib/**/*.rb",
    "data/*.json",
    "exe/*",
    "README.md",
    "CHANGELOG.md",
    "LICENSE"
  ]

  spec.bindir      = "exe"
  spec.executables = ["monovm-whois"]
  spec.require_paths = ["lib"]
end
