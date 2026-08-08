# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new

desc "Run the offline suite and the linter"
task default: %i[spec rubocop]

desc "Run the network-backed specs against live registries"
task :spec_network do
  ENV["RUN_NETWORK_TESTS"] = "1"
  sh "bundle exec rspec --tag network"
end

namespace :data do
  desc "Re-snapshot the IANA RDAP bootstrap registry (RFC 7484)"
  task :refresh_rdap do
    require "json"
    require "net/http"
    require_relative "lib/monovm/whois/paths"
    require_relative "lib/monovm/whois/registry/sources/iana_bootstrap"

    url = MonoVM::Whois::Registry::Sources::IanaBootstrap::BOOTSTRAP_URL
    path = MonoVM::Whois::Paths::RDAP_BOOTSTRAP

    puts "fetching #{url}"
    body = Net::HTTP.get(URI(url))

    document = JSON.parse(body)
    services = document.fetch("services")
    tlds = services.sum { |service| service[0].length }

    # Refuse to overwrite a good snapshot with a truncated or unexpected download.
    raise "unexpected payload: #{services.length} services, #{tlds} TLDs" if tlds < 500

    File.write(path, JSON.pretty_generate(document))
    puts "wrote #{path}"
    puts "  version:     #{document["version"]}"
    puts "  publication: #{document["publication"]}"
    puts "  services:    #{services.length} (#{tlds} TLDs)"
  end
end
