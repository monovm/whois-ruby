# frozen_string_literal: true

require "monovm/whois/cli"

RSpec.describe MonoVM::Whois::CLI do
  subject(:cli) { described_class.new(stdout: stdout, stderr: stderr) }

  let(:stdout) { StringIO.new }
  let(:stderr) { StringIO.new }

  # The CLI builds its own Checker from parsed options, so the transport is stubbed
  # at the Checker level rather than injected.
  def stub_lookups(results)
    allow(MonoVM::Whois::Checker).to receive(:new).and_return(
      instance_double(MonoVM::Whois::Checker, check_detailed: results)
    )
  end

  def result_for(name, status, **attributes)
    MonoVM::Whois::Result.new(
      domain: MonoVM::Whois::DomainName.parse(name),
      status: status,
      sld: name.split(".").first,
      tld: ".#{name.split(".").drop(1).join(".")}",
      **attributes
    )
  end

  describe "usage" do
    it "prints help and exits zero" do
      expect(cli.run(["--help"])).to eq(described_class::EXIT_OK)
      expect(stdout.string).to include("Usage: monovm-whois")
    end

    it "prints the version" do
      expect(cli.run(["--version"])).to eq(described_class::EXIT_OK)
      expect(stdout.string).to include(MonoVM::Whois::VERSION)
    end

    it "complains when given no domain" do
      expect(cli.run([])).to eq(described_class::EXIT_USAGE)
      expect(stderr.string).to include("give at least one domain")
    end

    it "complains about an unknown flag" do
      expect(cli.run(["--nonsense"])).to eq(described_class::EXIT_USAGE)
      expect(stderr.string).to include("invalid option")
    end

    it "rejects an unsupported --prefer value" do
      expect(cli.run(["a.com", "--prefer", "carrier-pigeon"]))
        .to eq(described_class::EXIT_USAGE)
    end

    it "reports how many TLDs are supported" do
      expect(cli.run(["--tld-count"])).to eq(described_class::EXIT_OK)
      expect(stdout.string).to match(/\d+ TLDs supported/)
    end
  end

  describe "text output" do
    it "prints one aligned row per name" do
      stub_lookups(
        "free.com" => result_for("free.com", :available),
        "taken.com" => result_for("taken.com", :registered)
      )

      expect(cli.run(%w[free.com taken.com --no-color])).to eq(described_class::EXIT_OK)
      expect(stdout.string).to include("free.com   available")
      expect(stdout.string).to include("taken.com  registered")
    end

    it "shows the deciding rule with --details" do
      verdict = MonoVM::Whois::Availability::Verdict.available(
        rule: "no_match", reason: "matched a not-found pattern"
      )
      stub_lookups("free.com" => result_for("free.com", :available, verdict: verdict))

      cli.run(%w[free.com --details --no-color])

      expect(stdout.string).to include("decided by: no_match")
      expect(stdout.string).to include("reason:     matched a not-found pattern")
    end

    it "colourises when asked" do
      stub_lookups("free.com" => result_for("free.com", :available))

      cli.run(%w[free.com --color])

      expect(stdout.string).to include("\e[32m")
    end

    it "leaves colour out when redirected" do
      stub_lookups("free.com" => result_for("free.com", :available))

      cli.run(%w[free.com])

      expect(stdout.string).not_to include("\e[")
    end
  end

  describe "JSON output" do
    it "emits parseable JSON" do
      stub_lookups("free.com" => result_for("free.com", :available))

      cli.run(%w[free.com --json])
      payload = JSON.parse(stdout.string)

      expect(payload.dig("free.com", "status")).to eq("available")
    end
  end

  describe "exit codes" do
    it "exits zero when every name got a real answer" do
      stub_lookups(
        "a.com" => result_for("a.com", :available),
        "b.com" => result_for("b.com", :registered),
        "c.com" => result_for("c.com", :premium)
      )

      expect(cli.run(%w[a.com b.com c.com])).to eq(described_class::EXIT_OK)
    end

    it "exits non-zero when a name came back unknown" do
      # So a shell script can tell "definitely free" from "could not find out".
      stub_lookups(
        "a.com" => result_for("a.com", :available),
        "b.com" => MonoVM::Whois::Result.unknown(
          MonoVM::Whois::DomainName.parse("b.com"), reason: "rate limited"
        )
      )

      expect(cli.run(%w[a.com b.com])).to eq(described_class::EXIT_INCONCLUSIVE)
    end

    it "exits non-zero for an invalid name" do
      stub_lookups("bad!" => result_for("bad.com", :invalid))

      expect(cli.run(["bad!"])).to eq(described_class::EXIT_INCONCLUSIVE)
    end
  end

  describe "options reaching the configuration" do
    it "passes --timeout through to every timeout" do
      captured = nil
      allow(MonoVM::Whois::Checker).to receive(:new) do |config:, **_rest|
        captured = config
        instance_double(MonoVM::Whois::Checker, check_detailed: {})
      end

      cli.run(%w[a.com --timeout 3.5])

      expect(captured.socket_connect_timeout).to eq(3.5)
      expect(captured.http_read_timeout).to eq(3.5)
    end

    it "passes --prefer through" do
      captured = nil
      allow(MonoVM::Whois::Checker).to receive(:new) do |config:, **_rest|
        captured = config
        instance_double(MonoVM::Whois::Checker, check_detailed: {})
      end

      cli.run(%w[a.com --prefer whois])

      expect(captured.prefer).to eq(:whois)
    end

    it "passes --tlds through" do
      captured = nil
      allow(MonoVM::Whois::Checker).to receive(:new) do |popular_tlds:, **_rest|
        captured = popular_tlds
        instance_double(MonoVM::Whois::Checker, check_detailed: {})
      end

      cli.run(%w[monovm --tlds .io,.dev])

      expect(captured).to eq(%w[.io .dev])
    end
  end
end
