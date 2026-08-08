# frozen_string_literal: true

module MonoVM
  module Whois
    # Locations of the data files shipped inside the gem.
    module Paths
      # +lib/monovm/whois/paths.rb+ -> the gem root.
      ROOT = File.expand_path("../../..", __dir__)
      DATA_DIR = File.join(ROOT, "data")

      # Curated WHOIS server list: TLD -> port 43 host plus availability markers.
      WHOIS_SERVERS = File.join(DATA_DIR, "whois_servers.json")

      # Snapshot of the IANA RDAP bootstrap registry (RFC 7484).
      # Refresh with +rake data:refresh_rdap+.
      RDAP_BOOTSTRAP = File.join(DATA_DIR, "rdap_bootstrap.json")

      # Environment variable pointing at an override file, so a deployment can
      # correct a stale registry entry without waiting for a gem release.
      OVERRIDE_ENV_VAR = "MONOVM_WHOIS_DEFINITIONS"

      class << self
        # @return [String, nil] the override file path, if one is configured
        def override
          path = ENV.fetch(OVERRIDE_ENV_VAR, nil)
          path.nil? || path.strip.empty? ? nil : path.strip
        end
      end
    end
  end
end
