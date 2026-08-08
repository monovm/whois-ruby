# frozen_string_literal: true

module MonoVM
  module Whois
    module Availability
      # The pattern tables the rules match against.
      #
      # Kept as frozen data, separate from the logic that reads it, for two reasons.
      # Registries change their wording without warning, so this is the file that
      # gets edited most often and it should be possible to edit it without
      # understanding the chain. And every table here is a claim about what some
      # registry actually emits, which is easier to review as a list than as
      # conditionals scattered through methods.
      module Patterns
        # Separator between a key and its value.
        #
        # Traficom (.fi) and several others align values by padding the key with
        # dots — +status.............: Registered+. A plain +status:+ match misses
        # that, and a missed "Registered" is read as availability, so every field
        # pattern is built through this rather than written literally.
        SEP = '[\s._·\-]*:[ \t]*'

        # Build a field-matching regexp source tolerant of padded keys and of
        # multiple spaces inside the key name.
        #
        #   field("name server") # matches "Name Server:", "name.server....:", "name  server :"
        #
        # @return [String] regexp source, not a Regexp, so callers can compose it
        def self.field(name)
          name.to_s.split(":").map { |part| Regexp.escape(part.strip).gsub("\\ ", '\s+') }
              .join(SEP).then { |source| "#{source}#{SEP}" }
        end

        # Value of a status-like field equals one of +values+.
        def self.status_is(*values)
          "(?:domain[\\s_]*)?(?:registration[\\s_]*)?status#{SEP}(?:#{values.join("|")})"
        end

        # ------------------------------------------------------------------
        # Server refused to answer (highest priority)
        # ------------------------------------------------------------------

        # Wording registries use when they will not answer: rate limits, blocked
        # clients, and port 43 endpoints retired in favour of RDAP.
        #
        # Without this table each of these responses would fall through the
        # heuristics and come back "available" — a rate-limited registry would
        # report every registered domain as free to register. This table is the
        # single most important correctness guard in the library.
        REFUSAL = [
          # Rate limiting: .pl, .lu, .cz, .ru, .dk and others.
          /request(?:s)?\s+limit\s+exceeded/i,
          /quer(?:y|ies)\s+limit\s+exceeded/i,
          /limit\s+exceeded/i,
          /maximum\s+quer(?:y|ies)\s+rate/i,
          /quer(?:y|ies)\s+rate\s+exceeded/i,
          /excessive\s+querying/i,
          /too\s+many\s+quer(?:y|ies)/i,
          /too\s+many\s+requests/i,
          /rate\s+limit(?:ed|ing)?/i,
          /lookup\s+quota/i,
          /quota\s+exceeded/i,
          /you\s+have\s+exceeded\s+/i,
          # Client blocked, or told to use a web form: .li, .ch, .it.
          /requests?\s+of\s+this\s+client\s+(?:are|is)\s+not\s+permitted/i,
          /access\s+to\s+this\s+whois\s+server\s+is\s+(?:denied|blocked)/i,
          /your\s+(?:ip|host|access)\s+has\s+been\s+(?:blocked|banned|denied)/i,
          /permission\s+denied/i,
          # Port 43 retired: .shop and other GMO / Identity Digital registries.
          /whois\s+service\s+has\s+been\s+retired/i,
          /(?:queries|service)\s+(?:are|is)\s+now\s+served\s+via\s+rdap/i,
          /please\s+use\s+(?:our\s+)?rdap/i,
          /rdap\s+base\s+url/i,
          # An HTTP error page delivered over port 43, or by a server that answered
          # 200 with an error document. Narrow on purpose: a bare "access denied"
          # can legitimately appear in a record whose details are withheld, so only
          # the unambiguous HTTP shapes count as a refusal.
          %r{\bhttp/1\.[01]\s+4\d\d\b}i,
          /\b40[13]\s+(?:forbidden|unauthori[sz]ed)\b/i,
          /\b429\s+too\s+many\s+requests\b/i,
          /\b50[0-4]\s+(?:internal\s+server\s+error|bad\s+gateway|service\s+unavailable)\b/i,
          # Transient server-side conditions.
          /server\s+(?:is\s+)?busy/i,
          /(?:please\s+)?try\s+again\s+later/i,
          /service\s+(?:is\s+)?temporarily\s+unavailable/i,
          /temporarily\s+unavailable/i,
          /database\s+(?:is\s+)?unavailable/i,
          /internal\s+server\s+error/i
        ].freeze

        # ------------------------------------------------------------------
        # Wrong server for this TLD
        # ------------------------------------------------------------------

        # The server answered, but it does not serve this TLD — so its answer says
        # nothing about the domain.
        UNSUPPORTED = [
          /tld\s+(?:is\s+)?not\s+supported/i,
          /extension\s+(?:is\s+)?not\s+supported/i,
          /unsupported\s+(?:tld|extension|domain)/i,
          /domain\s+(?:extension|type)\s+not\s+supported/i,
          /not\s+supported\s+by\s+this\s+whois\s+server/i,
          /no\s+whois\s+(?:server|service)\s+(?:available|found|known)/i,
          /whois\s+(?:server\s+)?not\s+(?:known|available|found)/i,
          /(?:server|service)\s+not\s+(?:available|found)\s+for/i,
          /whois\s+(?:service\s+)?not\s+available\s+for/i,
          /this\s+server\s+does\s+not\s+(?:serve|handle)/i
        ].freeze

        # Banners of the IP-address registries.
        #
        # Reaching one of these means a TLD is mapped to the wrong server. They
        # answer +%ERROR:101: no entries found+ to any domain query, which a naive
        # detector reads as availability for every name under that TLD.
        WRONG_REGISTRY_BANNERS = [
          /this\s+is\s+the\s+ripe\s+database\s+query\s+service/i,
          /the\s+objects\s+are\s+in\s+rpsl\s+format/i,
          /\[whois\.apnic\.net\]/i,
          /apnic\s+whois\s+service/i,
          /american\s+registry\s+for\s+internet\s+numbers/i,
          /whois\.arin\.net/i,
          /lacnic\s+whois\s+server/i,
          /afrinic\s+whois\s+server/i,
          /%error:101/i
        ].freeze

        # ------------------------------------------------------------------
        # The name is registered
        # ------------------------------------------------------------------

        # Statuses that mean the object exists, whatever state it is in. A domain in
        # redemption, on server hold or pending delete is emphatically not free.
        REGISTERED_STATUSES = %w[
          registered active connect client.* redemption.*
          pending.*delete server.?hold client.?hold allocated in\\s?use
          suspended locked expired quarantine
        ].freeze

        # General "this exists" wording, checked for every TLD.
        UNAVAILABILITY = [
          /---\s*not\s+available/i,
          /---\s*not\s+found/i,
          /---\s*domain\s+not\s+found/i,
          /\bnot\s+available\s+for\s+registration\b/i,
          /\bdomain\s+not\s+available\b/i,
          Regexp.new(status_is("not available", "unavailable", "taken"), Regexp::IGNORECASE),
          Regexp.new(status_is(*REGISTERED_STATUSES), Regexp::IGNORECASE),
          /this\s+domain\s+has\s+been\s+registered/i,
          /domain\s+(?:is\s+)?(?:already\s+|currently\s+)?registered/i,
          /\bis\s+registered\b/i,
          Regexp.new("#{field("registration")}registered", Regexp::IGNORECASE),
          # Registry restriction and reservation notices: the object exists but the
          # registry withholds its details. CIRA-backed registries answer
          # "Error code: 01044 ... usage restrictions applied" for reserved names.
          /usage\s+restrictions\s+applied/i,
          /usage\s+restrictions/i,
          /name\s+is\s+reserved/i,
          /reserved\s+(?:domain|name)/i,
          /domain\s+is\s+reserved/i,
          /blocked\s+by\s+the\s+registry/i
        ].freeze

        # Per-TLD wording that means registered. Consulted before the general table,
        # because a few registries use words that are ambiguous elsewhere.
        TLD_UNAVAILABILITY = {
          ".au" => [/---\s*not\s+available/i, /\bnot\s+available\b/i],
          ".com.au" => [/---\s*not\s+available/i, /\bnot\s+available\b/i],
          ".net.au" => [/---\s*not\s+available/i, /\bnot\s+available\b/i],
          ".org.au" => [/---\s*not\s+available/i, /\bnot\s+available\b/i],
          ".uk" => [/this\s+domain\s+has\s+been\s+registered/i, /\bregistered\b/i],
          ".co.uk" => [/this\s+domain\s+has\s+been\s+registered/i, /\bregistered\b/i],
          # DENIC. "Status: invalid" means the name cannot be registered as spelled;
          # it must never read as available.
          ".de" => [
            Regexp.new(status_is("connect", "registered", "active", "invalid", "failed"),
                       Regexp::IGNORECASE)
          ],
          ".nl" => [Regexp.new(status_is("active", "in\\s?use"), Regexp::IGNORECASE)],
          ".be" => [Regexp.new(status_is("registered", "allocated", "not\\s+available"), Regexp::IGNORECASE)],
          ".ca" => [/domain\s+registered/i, Regexp.new(status_is("registered"), Regexp::IGNORECASE)],
          ".fi" => [Regexp.new(status_is("registered"), Regexp::IGNORECASE)],
          ".ir" => [/\bdomain\s*:/i]
        }.freeze

        # Fields that only appear in a real record. Counting them is a strong signal:
        # a registry that answers with a registrar, a creation date and nameservers
        # is describing something that exists.
        REGISTRATION_INDICATORS = [
          "domain", "domain name", "ascii", "nserver", "nameserver", "name server",
          "registrar", "registrant", "registrar whois server", "registry domain id",
          "creation date", "created", "created on", "registered on", "registration date",
          "changed", "last updated", "updated date", "updated",
          "expiry date", "expires", "expires on", "registry expiry date", "paid-till",
          "admin contact", "technical contact", "billing contact", "tech-c", "admin-c",
          "dnssec", "sponsoring registrar", "holder"
        ].map { |name| Regexp.new(field(name), Regexp::IGNORECASE) }.freeze

        # The narrower set used to judge whether a response is a record at all.
        REGISTRATION_FIELDS = [
          "registrar", "registrant", "creation date", "created", "expiry date",
          "expires", "name server", "nameserver", "nserver", "admin contact",
          "technical contact", "paid-till", "sponsoring registrar"
        ].map { |name| Regexp.new(field(name), Regexp::IGNORECASE) }.freeze

        # ------------------------------------------------------------------
        # The name is available
        # ------------------------------------------------------------------

        # Phrases that state a name is unregistered. Matched against the response
        # with comment and banner lines removed, because registries put words like
        # "not found" in their legal preamble.
        AVAILABILITY_KEYWORDS = [
          "no match", "not found", "no data found", "no entries found",
          "no matching record", "no object found", "no such domain",
          "object does not exist", "nothing found", "no domain",
          "domain not found", "domain name not known", "not registered",
          "available for registration", "is available for registration",
          "is available for purchase", "domain is available",
          "domain has not been registered", "domain name has not been registered",
          "domain does not exist", "does not exist in database", "was not found",
          "not exist", "object_not_found", "free",
          # Spanish and Portuguese registries.
          "no se encontro el objeto", "el dominio no se encuentra registrado",
          "no está registrado", "dominio no registrado",
          # French, German, Dutch.
          "aucun objet trouvé", "nicht vergeben", "is vrij", "vrij"
        ].map(&:freeze).freeze

        # Regexp forms, matched against the whole response. Broader than the keyword
        # list because whitespace between words varies by registry.
        NO_MATCH = [
          /\bno\s+match\b/i,
          /\bnot\s+found\b/i,
          /\bno\s+data\s+found\b/i,
          /\bno\s+entries\s+found\b/i,
          /\bno\s+matching\s+record/i,
          /\bno\s+object\s+found\b/i,
          /object\s+does\s+not\s+exist/i,
          /\bno\s+such\s+domain\b/i,
          /domain\s+not\s+found/i,
          /domain\s+name\s+not\s+known/i,
          /domain\s+(?:name\s+)?has\s+not\s+been\s+registered/i,
          /domain\s+(?:is\s+)?available/i,
          /\bis\s+available\s+for\b/i,
          /domain\s+does\s+not\s+exist/i,
          /does\s+not\s+exist\s+in\s+database/i,
          /\bwas\s+not\s+found\b/i,
          /object_not_found/i,
          /no\s+se\s+encontro\s+el\s+objeto/i,
          /el\s+dominio\s+no\s+se\s+encuentra\s+registrado/i,
          /no\s+está\s+registrado/i,
          /---\s*available/i,
          /%error:103/i
        ].freeze

        # An explicit status field saying the name is free.
        STATUS_AVAILABLE = [
          Regexp.new(status_is("available", "free", "not\\s+registered", "no\\s+object"),
                     Regexp::IGNORECASE),
          /availability#{SEP}available/i,
          /state#{SEP}available/i,
          /status\s*=\s*available/i,
          /\bstatus:\s*AVAILABLE\b/
        ].freeze

        # Per-TLD availability wording, consulted late. Several of these are single
        # words like "available" that would be far too loose as a general rule but
        # are unambiguous in a given registry's output format.
        TLD_AVAILABILITY = {
          ".com" => [/no\s+match\s+for/i, /domain\s+not\s+found/i],
          ".net" => [/no\s+match\s+for/i, /domain\s+not\s+found/i],
          ".org" => [/domain\s+not\s+found/i, /\bnot\s+found\b/i],
          ".edu" => [/no\s+match\s+for/i],
          ".uk" => [/\bno\s+match\b/i, /this\s+domain\s+is\s+available/i],
          ".co.uk" => [/\bno\s+match\b/i, /this\s+domain\s+is\s+available/i],
          ".de" => [/is\s+available\s+for\s+registration/i, /status#{SEP}free/i],
          ".fr" => [/\bnot\s+found\b/i, /available/i],
          ".it" => [/\bavailable\b/i, /status#{SEP}available/i],
          ".au" => [/---\s*available/i, /is\s+available\s+for\s+registration/i],
          ".com.au" => [/is\s+available\s+for\s+registration/i, /\bavailable\b/i],
          ".be" => [/status#{SEP}available/i, /\bfree\b/i],
          ".ca" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".ch" => [/---\s*1:/i, /\bavailable\b/i, /\bwe\s+do\s+not\s+have\s+an\s+entry\b/i],
          ".li" => [/\bavailable\b/i, /\bwe\s+do\s+not\s+have\s+an\s+entry\b/i],
          ".eu" => [/status#{SEP}available/i, /\bavailable\b/i],
          ".nl" => [/\bis\s+free\b/i, /\bavailable\b/i],
          ".dk" => [/\bno\s+entries\s+found\b/i, /\bavailable\b/i],
          ".no" => [/\bno\s+match\b/i, /\bavailable\b/i],
          ".se" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".nu" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".fi" => [/\bavailable\b/i, /domain\s+not\s+found/i],
          ".pt" => [/\bavailable\b/i, /\bno\s+match\b/i],
          ".es" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".jp" => [/no\s+match!!/i, /\bno\s+match\b/i],
          ".cn" => [/no\s+matching\s+record/i, /\bnot\s+found\b/i],
          ".in" => [/\bnot\s+found\b/i, /\bno\s+data\s+found\b/i],
          ".hk" => [/the\s+domain\s+has\s+not\s+been\s+registered/i],
          ".tw" => [/\bno\s+found\b/i, /\bnot\s+found\b/i],
          ".kr" => [/\bnot\s+found\b/i, /above\s+domain\s+name\s+is\s+not\s+registered/i],
          ".sg" => [/---\s*not\s+found/i, /domain\s+not\s+found/i],
          ".my" => [/does\s+not\s+exist\s+in\s+database/i],
          ".ph" => [/domain\s+is\s+available/i],
          ".th" => [/no\s+match\s+found/i],
          ".vn" => [/\bavailable\b/i, /\bnot\s+found\b/i],
          ".id" => [/domain\s+not\s+found/i, /\bavailable\b/i],
          ".us" => [/\bnot\s+found\b/i, /domain\s+not\s+found/i],
          ".mx" => [/no_se_encontro_el_objeto/i, /\bnot\s+found\b/i],
          ".br" => [/no\s+match\s+for/i, /domain\s+not\s+found/i],
          ".ar" => [/el\s+dominio\s+no\s+se\s+encuentra\s+registrado/i],
          ".co" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".cl" => [/\bno\s+entries\s+found\b/i, /\bavailable\b/i],
          ".pe" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".ru" => [/\bno\s+entries\s+found\b/i, /\bnot\s+found\b/i],
          ".su" => [/\bno\s+entries\s+found\b/i],
          ".pl" => [/no\s+information\s+available/i, /\bavailable\b/i],
          ".cz" => [/\bno\s+entries\s+found\b/i, /\bavailable\b/i],
          ".sk" => [/domain\s+not\s+found/i, /\bavailable\b/i],
          ".hu" => [/\bno\s+match\b/i, /\bavailable\b/i],
          ".ro" => [/\bno\s+entries\s+found\b/i, /\bavailable\b/i],
          ".rs" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".me" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".md" => [/\bno\s+object\s+found\b/i, /\bavailable\b/i],
          ".ua" => [/\bno\s+entries\s+found\b/i, /\bavailable\b/i],
          ".za" => [/\bavailable\b/i, /\bnot\s+found\b/i],
          ".co.za" => [/\bavailable\b/i, /\bnot\s+found\b/i],
          ".ng" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".ke" => [/\bno\s+object\s+found\b/i, /\bavailable\b/i],
          ".ma" => [/\bno\s+object\s+found\b/i, /\bavailable\b/i],
          ".nz" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".ws" => [/the\s+queried\s+object\s+does\s+not\s+exist/i],
          ".cc" => [/\bno\s+match\b/i, /\bavailable\b/i],
          ".tv" => [/\bno\s+match\b/i, /\bavailable\b/i],
          ".to" => [/no\s+match\s+for/i, /\bavailable\b/i],
          ".im" => [/\bwas\s+not\s+found\b/i, /\bavailable\b/i],
          ".io" => [/---\s*domain\s+not\s+found/i, /\bavailable\b/i],
          ".sh" => [/domain\s+not\s+found/i, /\bavailable\b/i],
          ".ac" => [/domain\s+not\s+found/i, /\bavailable\b/i],
          ".gg" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".je" => [/\bnot\s+found\b/i, /\bavailable\b/i],
          ".tk" => [/domain\s+name\s+not\s+known/i, /\bavailable\b/i],
          ".cm" => [/\bnot\s+registered\b/i, /\bavailable\b/i],
          ".ir" => [/\bno\s+entries\s+found\b/i],
          ".gr" => [/\bnot\s+exist\b/i],
          ".is" => [/\bno\s+entries\s+found\b/i],
          ".lt" => [/\bavailable\b/i, /status#{SEP}available/i],
          ".lv" => [/status#{SEP}free/i, /\bavailable\b/i],
          ".ee" => [/\bdomain\s+not\s+found\b/i],
          ".bg" => [/\bdoes\s+not\s+exist\b/i],
          ".hr" => [/\bnot\s+found\b/i],
          ".si" => [/\bno\s+entries\s+found\b/i],
          ".at" => [/\bnothing\s+found\b/i, /status#{SEP}free/i],
          ".lu" => [/\bno\s+such\s+domain\b/i]
        }.freeze

        # ------------------------------------------------------------------
        # Guards
        # ------------------------------------------------------------------

        # Text that means "this response is a notice, not a record". Absence of
        # registration fields is only evidence of availability when none of these is
        # present — an error page has no registration fields either.
        ERROR_OR_RESTRICTION = [
          /error\s+code#{SEP}/i,
          /error\s+message#{SEP}/i,
          /usage\s+restrictions/i,
          /please\s+see\s+your\s+registrar/i,
          /please\s+contact/i,
          /\bis\s+reserved\b/i,
          /reserved\s+name/i,
          /\brestricted\b/i,
          /access\s+denied/i,
          /not\s+authori[sz]ed/i,
          /unauthori[sz]ed/i,
          /\bmalformed\b/i,
          /invalid\s+(?:query|request|domain|input)/i,
          /syntax\s+error/i
        ].freeze

        # Line prefixes that mark registry commentary rather than record data.
        # Registries routinely use words like "not found" in their legal preamble.
        COMMENT_PREFIXES = ["%", "#", ";", ">>>", "---", "*", "//"].freeze

        # Boilerplate lines that survive prefix stripping but are still commentary.
        BOILERPLATE = [
          /available\s+on\s+web\s+at/i,
          /find\s+the\s+terms\s+and\s+conditions/i,
          /terms\s+of\s+use/i,
          /by\s+submitting\s+(?:a|this|any)\s+quer/i,
          /for\s+more\s+information\s+(?:on|about)\s+whois/i,
          /whois\s+(?:database|server)\s+(?:is\s+)?provided/i,
          /the\s+data\s+(?:in|contained)/i,
          /this\s+(?:data|information)\s+is\s+provided/i,
          /notice#{SEP}/i,
          /copyright/i,
          /all\s+rights\s+reserved/i,
          /personal\s+data/i,
          /gdpr/i,
          /redacted\s+for\s+privacy/i
        ].freeze

        # ------------------------------------------------------------------
        # RDAP
        # ------------------------------------------------------------------

        # Keys that only appear in an RDAP object describing a real registration.
        RDAP_REGISTRATION_KEYS = %w[
          ldhName handle nameservers secureDNS entities events status
        ].freeze

        # RDAP error codes that mean "no such object", i.e. the name is free.
        RDAP_NOT_FOUND_CODES = [404].freeze
      end
    end
  end
end
