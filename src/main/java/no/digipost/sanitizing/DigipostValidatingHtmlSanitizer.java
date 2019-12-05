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

import no.digipost.sanitizing.exception.HTMLValidationException;
import no.digipost.sanitizing.exception.ValidationException;
import no.digipost.sanitizing.internal.ErrorCollectingHtmlChangeListener;
import no.digipost.sanitizing.internal.PolicyFactoryProvider;
import org.owasp.html.PolicyFactory;

public class DigipostValidatingHtmlSanitizer {

    public static void main(String[] args) {
        final String sanitize = new DigipostValidatingHtmlSanitizer()
            .sanitize(args[0], PolicyFactoryProvider.API_HTML);

        System.out.println(sanitize);
    }

    /**
     * Validate and sanitize HTML according to the given policy. Records all registered HTML changes and reports these as validations errors.
     * <p>
     * Note that it both validates (throws Exceptions) _and_ sanitizes (returns modified HTML), as there are some minor things that are not reported correctly from the validation framework (i.e. duplicate attributes).
     * <p>
     * We do validation in addition to sanitazion for legacy reasons (we originally did only validation) and because we want to avoid tampering with document contets.
     */
    public String sanitize(final String html, final PolicyFactory policy) throws ValidationException {
        ErrorCollectingHtmlChangeListener errorCollector = PolicyFactoryProvider.errorCollector();

        // https://github.com/OWASP/java-html-sanitizer/issues/103
        String doctype = "<!doctype html>";
        if (!html.trim().toLowerCase().startsWith(doctype)) {
            doctype = "";
        }

        //Will throw CSSValidationException if css is invalid (see StyleElementPreprocessor).
        String sanitizedHtml = doctype + policy.sanitize(html, errorCollector, null);

        if (errorCollector.hasErrors()) {
            throw new HTMLValidationException(errorCollector.getErrors());
        }

        return sanitizedHtml;
    }
}
