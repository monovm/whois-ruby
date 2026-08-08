# frozen_string_literal: true

if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/spec/"
    enable_coverage :branch
  end
end

require "monovm/whois"
require "webmock/rspec"

# Nothing in the offline suite may touch the network. WebMock covers HTTP; the
# socket transport is only ever exercised against a loopback server started by the
# spec itself, or replaced by a fake.
WebMock.disable_net_connect!(allow_localhost: true)

Dir[File.join(__dir__, "support", "**", "*.rb")].each { |file| require file }

RSpec.configure do |config|
  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.disable_monkey_patching!
  config.warnings = false
  config.order = :random
  Kernel.srand config.seed

  config.include ResponseBuilder

  # Live registry lookups are opt-in: they are slow, they depend on someone else's
  # uptime, and they consume rate-limit budget.
  config.filter_run_excluding(network: true) unless ENV["RUN_NETWORK_TESTS"]

  # The module-level facade memoises a client and a configuration; leaking either
  # between examples makes failures depend on ordering.
  config.after do
    MonoVM::Whois.reset!
  end
end
