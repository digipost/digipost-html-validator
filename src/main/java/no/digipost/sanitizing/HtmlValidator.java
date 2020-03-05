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

    private DigipostValidatingHtmlSanitizer digipostValidatingHtmlSanitizer;
    private Clock clock;

    public HtmlValidator() {
        this(Clock.systemDefaultZone());
    }

    public HtmlValidator(Clock clock) {
        this.clock = clock;
        this.digipostValidatingHtmlSanitizer = new DigipostValidatingHtmlSanitizer();
    }

    public HtmlValidationResult valider(byte[] content) {
        try {
            final String input = new String(content, StandardCharsets.UTF_8);
            final String output = this.digipostValidatingHtmlSanitizer.sanitize(input, PolicyFactoryProvider.getPolicyFactory(clock.instant()));
            if (input.equals(output)) {
                return HTML_EVERYTHING_OK;
            } else {
                return new HtmlValidationResult(output);
            }
        } catch (ValidationException e) {
            return new HtmlValidationResult(e);
        }
    }
}
