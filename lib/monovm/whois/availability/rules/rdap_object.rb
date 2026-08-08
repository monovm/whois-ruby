# frozen_string_literal: true

require_relative "../rule"

module MonoVM
  module Whois
    module Availability
      module Rules
        # Reads an RDAP response, which says outright whether the object exists.
        #
        # This is why the library prefers RDAP. Every other rule in the chain infers
        # a verdict from prose that varies by registry, by year and sometimes by
        # query. RDAP does not need inference: a registered domain is a JSON object
        # with an +objectClassName+ of +"domain"+, and an unregistered one is an
        # error document with +errorCode+ 404 (RFC 7480 §5.3, RFC 9083 §6). Both
        # answers are definitive, so this rule sits above all the pattern matching.
        class RdapObject < Rule
          def call(context)
            return nil unless context.rdap?

            document = context.json

            # An HTTP 404 is RDAP's "no such domain", whether or not it carried a body.
            if document.nil?
              return nil unless Patterns::RDAP_NOT_FOUND_CODES.include?(context.http_status)

              return available(
                reason: "RDAP answered HTTP 404: no such domain",
                evidence: "HTTP #{context.http_status}"
              )
            end

            verdict_for_error(document, context) || verdict_for_object(document)
          end

          private

          def verdict_for_error(document, _context)
            code = document["errorCode"]
            return nil if code.nil?

            code = code.to_i

            if Patterns::RDAP_NOT_FOUND_CODES.include?(code)
              return available(
                reason: "RDAP errorCode 404: no such domain",
                evidence: error_evidence(document, code)
              )
            end

            # Any other error code is the server declining, not an answer: 429 for
            # rate limiting, 403 for a blocked client, 400 for a query it disliked.
            unknown(
              reason: "RDAP returned errorCode #{code}",
              evidence: error_evidence(document, code)
            )
          rescue TypeError
            nil
          end

          def verdict_for_object(document)
            return nil unless describes_domain?(document)

            present = Patterns::RDAP_REGISTRATION_KEYS.count { |key| document.key?(key) }

            # A conformant domain object always carries an ldhName plus at least
            # something about its state; requiring two keys avoids treating a bare
            # help or notice document as a registration.
            return nil unless present >= 2

            registered(
              reason: "RDAP returned a domain object",
              evidence: document["ldhName"] || document["handle"]
            )
          end

          def describes_domain?(document)
            object_class = document["objectClassName"].to_s.downcase
            return true if object_class == "domain"

            # Some registries omit objectClassName but are unmistakably describing a
            # registration; rdapConformance plus an ldhName is enough.
            document.key?("ldhName") && document.key?("rdapConformance")
          end

          def error_evidence(document, code)
            title = document["title"] || Array(document["description"]).first
            [code, title].compact.join(" ")
          end
        end
      end
    end
  end
end
