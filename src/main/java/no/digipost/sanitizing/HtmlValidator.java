/**
 * Copyright (C) Posten Norge AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package no.digipost.sanitizing;

import no.digipost.sanitizing.exception.ValidationException;
import no.digipost.sanitizing.internal.PolicyFactoryProvider;

import java.nio.charset.StandardCharsets;
import java.time.Clock;

import static no.digipost.sanitizing.HtmlValidationResult.HTML_EVERYTHING_OK;

public class HtmlValidator {

    private final DigipostValidatingHtmlSanitizer digipostValidatingHtmlSanitizer;
    private final Clock clock;

    public HtmlValidator() {
        this(Clock.systemDefaultZone());
    }

    public HtmlValidator(Clock clock) {
        this.clock = clock;
        this.digipostValidatingHtmlSanitizer = new DigipostValidatingHtmlSanitizer();
    }

    /**
     * Validate html and check sanitation differences.
     *
     * Same as <code>valider(content, false</code>.
     *
     * @param content HTML content to validate.
     * @return result of validation.
     */
    public HtmlValidationResult valider(byte[] content) {
        return valider(content, false);
    }

    /**
     *
     * Validate HTML and check whether sanitations would produce differences.
     *
     * @param content Html contents to validate
     * @param includeSanitizedOnDifference whether the entire sanitized html
     *        should be included in the validation result. It can be viewed as
     *        part of {@link HtmlValidationResult#toString}, but should normally
     *        be skipped, due to size or sensitive data exposure risk.
     *
     * @return result of validation.
     */
    public HtmlValidationResult valider(byte[] content, boolean includeSanitizedOnDifference) {
        try {
            final String input = new String(content, StandardCharsets.UTF_8);
            final String output = this.digipostValidatingHtmlSanitizer.sanitize(input, PolicyFactoryProvider.getPolicyFactory(clock.instant()));
            if (input.equals(output)) {
                return HTML_EVERYTHING_OK;
            } else {
                return new HtmlValidationResult(includeSanitizedOnDifference ? output:
                    "Sanitized html result not shown. Specify the "
                    + "includeSanitizedOnDifference parameter as true, if you need that.");
            }
        } catch (ValidationException e) {
            return new HtmlValidationResult(e);
        }
    }
}
