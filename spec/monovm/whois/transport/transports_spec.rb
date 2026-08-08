# frozen_string_literal: true

require "socket"

RSpec.describe "transports" do
  describe MonoVM::Whois::Transport::WhoisSocket do
    subject(:transport) { described_class.new(connect_timeout: 2, read_timeout: 2) }

    # A real loopback WHOIS server. Cheaper than mocking Socket, and it actually
    # exercises the read loop, the CRLF the protocol requires, and the close.
    def serve(&handler)
      server = TCPServer.new("127.0.0.1", 0)
      thread = Thread.new do
        client = server.accept
        query = client.gets.to_s.chomp
        handler.call(client, query)
      ensure
        begin
          client&.close
        rescue IOError
          nil
        end
      end

      yield_endpoint = MonoVM::Whois::Endpoint.parse("socket://127.0.0.1:#{server.addr[1]}")
      [yield_endpoint, server, thread]
    end

    it "sends the query and reads the whole answer" do
      received = nil
      point, server, thread = serve do |client, query|
        received = query
        client.write("Domain Name: EXAMPLE.COM\r\nRegistrar: Example\r\n")
      end

      response = transport.fetch(query: "example.com", endpoint: point)

      expect(received).to eq("example.com")
      expect(response.body).to include("Domain Name: EXAMPLE.COM")
      expect(response.text).to include("Registrar: Example")
      expect(response.elapsed).to be_a(Float)
    ensure
      thread&.join(2)
      server&.close
    end

    it "normalises CRLF in #text but keeps #body verbatim" do
      point, server, thread = serve { |client, _q| client.write("a\r\nb\r\n") }

      response = transport.fetch(query: "example.com", endpoint: point)

      expect(response.text).to eq("a\nb\n")
      expect(response.body).to eq("a\r\nb\r\n")
    ensure
      thread&.join(2)
      server&.close
    end

    it "reads an answer larger than one chunk" do
      big = "Domain Name: example.com\r\n#{"x = #{"y" * 100}\r\n" * 500}"
      point, server, thread = serve { |client, _q| client.write(big) }

      response = transport.fetch(query: "example.com", endpoint: point)

      expect(response.body.length).to eq(big.length)
    ensure
      thread&.join(2)
      server&.close
    end

    it "decodes a Latin-1 record rather than mangling it" do
      point, server, thread = serve do |client, _q|
        client.write("Registrant: Bj\xF6rk Gu\xF0mundsd\xF3ttir\r\n".b)
      end

      response = transport.fetch(query: "example.is", endpoint: point)

      expect(response.text).to include("Björk")
    ensure
      thread&.join(2)
      server&.close
    end

    it "raises EmptyResponseError when the server says nothing" do
      # An empty record is not evidence that a domain is unregistered.
      point, server, thread = serve { |client, _q| client.close }

      expect { transport.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::EmptyResponseError)
    ensure
      thread&.join(2)
      server&.close
    end

    it "raises ConnectionError when nothing is listening" do
      # Port 1 on loopback: reliably closed.
      point = MonoVM::Whois::Endpoint.parse("socket://127.0.0.1:1")

      expect { transport.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::ConnectionError)
    end

    it "keeps a partial record when the server hangs mid-answer" do
      fast = described_class.new(connect_timeout: 2, read_timeout: 0.3)
      point, server, thread = serve do |client, _q|
        client.write("Domain Name: example.com\r\nRegistrar: X\r\n")
        sleep 2
      end

      response = fast.fetch(query: "example.com", endpoint: point)

      expect(response.text).to include("Domain Name: example.com")
    ensure
      thread&.kill
      server&.close
    end

    it "raises TimeoutError when the server sends nothing at all in time" do
      fast = described_class.new(connect_timeout: 2, read_timeout: 0.3)
      point, server, thread = serve { |_client, _q| sleep 2 }

      expect { fast.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::TimeoutError)
    ensure
      thread&.kill
      server&.close
    end

    it "only serves socket endpoints" do
      expect(transport.supports?(MonoVM::Whois::Endpoint.parse("socket://a.test"))).to be(true)
      expect(transport.supports?(MonoVM::Whois::Endpoint.parse("https://a.test/"))).to be(false)
    end
  end

  describe MonoVM::Whois::Transport::RdapHttp do
    subject(:transport) { described_class.new(open_timeout: 2, read_timeout: 2) }

    let(:point) { MonoVM::Whois::Endpoint.parse("https://rdap.test/domain/") }

    it "fetches a domain object" do
      stub_request(:get, "https://rdap.test/domain/example.com")
        .to_return(status: 200, body: '{"objectClassName":"domain","ldhName":"example.com"}',
                   headers: { "Content-Type" => "application/rdap+json" })

      response = transport.fetch(query: "example.com", endpoint: point)

      expect(response.status).to eq(200)
      expect(response.json["ldhName"]).to eq("example.com")
      expect(response).to be_rdap
    end

    it "sends an RDAP Accept header and a User-Agent" do
      stub = stub_request(:get, "https://rdap.test/domain/example.com")
             .with(headers: { "Accept" => %r{application/rdap\+json} })
             .to_return(status: 200, body: "{}")

      transport.fetch(query: "example.com", endpoint: point)

      expect(stub).to have_been_requested
    end

    it "returns a 404 body, because that is RDAP's no-such-domain answer" do
      stub_request(:get, "https://rdap.test/domain/free.com")
        .to_return(status: 404, body: '{"errorCode":404,"title":"Domain not found"}')

      response = transport.fetch(query: "free.com", endpoint: point)

      expect(response.status).to eq(404)
      expect(response.json["errorCode"]).to eq(404)
    end

    it "returns a bodyless 404 rather than raising" do
      stub_request(:get, "https://rdap.test/domain/free.com").to_return(status: 404, body: "")

      expect(transport.fetch(query: "free.com", endpoint: point).status).to eq(404)
    end

    [401, 403, 405, 406, 429].each do |status|
      it "raises ServerRefusedError on HTTP #{status}, so it cannot be read as available" do
        stub_request(:get, "https://rdap.test/domain/example.com")
          .to_return(status: status, body: "<html>denied</html>")

        expect { transport.fetch(query: "example.com", endpoint: point) }
          .to raise_error(MonoVM::Whois::ServerRefusedError)
      end
    end

    it "raises ServerRefusedError on a 5xx" do
      stub_request(:get, "https://rdap.test/domain/example.com").to_return(status: 503)

      expect { transport.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::ServerRefusedError, /503/)
    end

    it "raises EmptyResponseError on an empty 200" do
      stub_request(:get, "https://rdap.test/domain/example.com").to_return(status: 200, body: "  ")

      expect { transport.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::EmptyResponseError)
    end

    it "follows a redirect, which registries use to hand off to a registrar" do
      stub_request(:get, "https://rdap.test/domain/example.com")
        .to_return(status: 301, headers: { "Location" => "https://other.test/domain/example.com" })
      stub_request(:get, "https://other.test/domain/example.com")
        .to_return(status: 200, body: '{"ldhName":"example.com"}')

      expect(transport.fetch(query: "example.com", endpoint: point).status).to eq(200)
    end

    it "stops following redirects eventually" do
      stub_request(:get, %r{https://rdap\.test/domain/example\.com})
        .to_return(status: 301, headers: { "Location" => "https://rdap.test/domain/example.com" })

      # The final hop is still a 301, which is not a refusal, so it comes back as-is
      # rather than looping forever.
      expect(transport.fetch(query: "example.com", endpoint: point).status).to eq(301)
    end

    it "maps a timeout onto TimeoutError" do
      stub_request(:get, "https://rdap.test/domain/example.com").to_timeout

      expect { transport.fetch(query: "example.com", endpoint: point) }
        .to raise_error(MonoVM::Whois::ConnectionError)
    end

    it "only serves HTTP endpoints" do
      expect(transport.supports?(point)).to be(true)
      expect(transport.supports?(MonoVM::Whois::Endpoint.parse("socket://a.test"))).to be(false)
    end
  end

  describe MonoVM::Whois::Transport::Factory do
    subject(:factory) { described_class.new }

    it "picks the socket transport for a socket endpoint" do
      transport = factory.for(MonoVM::Whois::Endpoint.parse("socket://a.test"))

      expect(transport).to be_a(MonoVM::Whois::Transport::WhoisSocket)
    end

    it "picks the HTTP transport for an https endpoint" do
      transport = factory.for(MonoVM::Whois::Endpoint.parse("https://a.test/domain/"))

      expect(transport).to be_a(MonoVM::Whois::Transport::RdapHttp)
    end

    it "raises for an endpoint nothing can serve" do
      unusable = instance_double(MonoVM::Whois::Endpoint, to_s: "gopher://a.test")
      allow(unusable).to receive_messages(socket?: false, http?: false)

      expect { factory.for(unusable) }.to raise_error(MonoVM::Whois::Error, /no transport/)
    end
  end
end
