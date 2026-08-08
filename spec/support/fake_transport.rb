# frozen_string_literal: true

# A transport that answers from a script instead of a network.
#
# The whole point of {MonoVM::Whois::Transport::Base} being a one-method interface is
# that this class can stand in for it everywhere, which is what lets the suite cover
# the client, the checker and the rule chain without a socket.
class FakeTransport < MonoVM::Whois::Transport::Base
  attr_reader :calls

  # @param bodies [Hash{String => String, Hash, Exception, Proc}] keyed by query.
  #   A String or Hash becomes a response body; an Exception class or instance is
  #   raised; a Proc is called with (query, endpoint).
  # @param default [Object, nil] used for any query not in +bodies+
  # @param status [Integer, nil] HTTP status to report on responses
  def initialize(bodies = {}, default: nil, status: nil)
    @bodies = bodies
    @default = default
    @status = status
    @calls = []
    super()
  end

  def supports?(_endpoint)
    true
  end

  def fetch(query:, endpoint:)
    @calls << { query: query, endpoint: endpoint.to_s }

    scripted = @bodies.fetch(query) { @bodies.fetch(endpoint.to_s, @default) }
    raise MonoVM::Whois::EmptyResponseError, "no scripted answer for #{query}" if scripted.nil?

    resolve(scripted, query, endpoint)
  end

  # How many times this transport was asked anything.
  def call_count
    calls.length
  end

  def queried?(query)
    calls.any? { |call| call[:query] == query }
  end

  private

  def resolve(scripted, query, endpoint)
    case scripted
    when Class
      raise scripted, "scripted failure for #{query}" if scripted <= Exception

      raise ArgumentError, "cannot script #{scripted}"
    when Exception then raise scripted
    when Proc then resolve(scripted.call(query, endpoint), query, endpoint)
    when MonoVM::Whois::Response then scripted
    when Hash then build(JSON.generate(scripted), query, endpoint, @status || 200)
    else build(scripted.to_s, query, endpoint, @status)
    end
  end

  def build(body, query, endpoint, status)
    MonoVM::Whois::Response.new(
      body: body,
      endpoint: endpoint,
      query: query,
      status: endpoint.http? ? (status || 200) : nil
    )
  end
end

# A transport factory that hands out one fake for every endpoint.
class FakeTransportFactory
  attr_reader :transport

  def initialize(transport)
    @transport = transport
  end

  def for(_endpoint)
    transport
  end
end
