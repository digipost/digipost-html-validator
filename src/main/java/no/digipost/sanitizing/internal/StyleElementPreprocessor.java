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
package no.digipost.sanitizing.internal;

import no.digipost.sanitizing.exception.CSSValidationException;
import org.owasp.html.HtmlStreamEventProcessor;
import org.owasp.html.HtmlStreamEventReceiver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static no.digipost.sanitizing.internal.ApiHtmlValidatorPolicy.CSS_PROPERTY_WHITELIST;

/**
 * Denne klassen tar av seg sanitering av innholdet i style-elementet. Saniteringen som blir utført er blant annet basert på denne cheat sheeten fra OWASP:
 * https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.md
 * <p>
 * Angånde HTML entity encoding: OWASP foreslår å encode både ' og ".
 * Hvis dette blir håndhevet medfører det imidlertid problemer siden browsere ikke takler html entity encoding i css-en.
 * Vi har derfor valgt å ikke entity encode disse to tegnene. Risikoen for å tillatte de er begrenset, da det må brukes i kombinasjon
 * med andre spesialtegn som vi html entity encoder. En ny vurdering rundt html entity encoding burde imidlertid tas om man beslutter å åpne opp html-innsending for alle/majoriteten av virksomheter.
 * Eksempler på når det kan være behov for ' eller " er ved bruk av propertyen font-family eller content.
 * <p>
 * For å benytte seg av HTML i utgangspunktet krever vi at virksomhetsinnstillingen `brev.kanSendeHtml` er aktivert for virksomheten.
 * Det stilles noen krav til CSS-en:
 * Må oppfylle regex-er definert under.
 * Declaration kan ikke inneholde ord definert i WORDS_IN_VALUE_BLACKLIST
 * Note: Kommentarer i css-en er ikke tillatt.
 */
final class StyleElementPreprocessor implements HtmlStreamEventProcessor {
    @Override
    public HtmlStreamEventReceiver wrap(HtmlStreamEventReceiver receiver) {
        return new StyleElementReceiver(receiver);
    }

    public static class StyleElementReceiver implements HtmlStreamEventReceiver {

        private static final String STYLE_TAG = "style";

        private static final Set<String> WORDS_IN_VALUE_BLACKLIST = new HashSet<>(Arrays.asList("javascript", "expression", "url(", "http://", "https://", "/*", "*/"));
        private static final Map<String, String> HTML_ESCAPE_CHARS = new HashMap<>();

        static{
            HTML_ESCAPE_CHARS.put("&", "&amp;");
            HTML_ESCAPE_CHARS.put("<", "&lt;");
            HTML_ESCAPE_CHARS.put(">", "&gt;");
            HTML_ESCAPE_CHARS.put("/", "&#x2F;");
        };

        // check that css is valid format. No dangling selectors (i.e. text) : (?:([\.\#\-\w\s\: \[\],]+)\s*\{([^}]+)\}\s*)+
        private static final Pattern completeCssPattern = Pattern.compile("(?:([\\.\\#\\-\\w\\s\\: \\[\\],]+)\\s*\\{([^}]+)\\}\\s*)+");

        // Only difference to completeCssPattern is the non-capturing group such that we can use find() to get capture groups one by one:
        // Selector to group 1, all of its content to group 2. Regex without java escaping: ([\.\#\-\w\s\: \[\],]+)\s*\{([^}]+)\}\s*
        private static final Pattern selectorAndContentPattern = Pattern.compile("([\\.\\#\\-\\w\\s\\: \\[\\],]+)\\s*\\{([^}]+)\\}\\s*");

        // Property to group 1, values to group 2. Regex without java escaping: \s*([\w- ]*)\:([\w\d\. \,\%\#\-\:\"\'\(\)\!\\]*)\;
        private static final Pattern propertyValuePattern = Pattern.compile("\\s*([\\w- ]*)\\:([\\w\\d\\. \\,\\%\\#\\-\\:\\\"\\'\\(\\)\\!\\\\]*)\\;");

        private static final Logger log = LoggerFactory.getLogger(no.digipost.sanitizing.internal.StyleElementPreprocessor.StyleElementReceiver.class);

        private final HtmlStreamEventReceiver receiver;
        private boolean inStyleTag;


        StyleElementReceiver(HtmlStreamEventReceiver receiver) {
            this.receiver = receiver;
        }

        /**
         * @param css The content of the \<style>-element (pure css)
         * @return sanitized version of content
         */
        public static String validateAndSanitizeCss(String css) {
            List<String> validationErrors = new ArrayList<>();

            validateCss(css, validationErrors);

            if (!validationErrors.isEmpty()) {
                throw new CSSValidationException(validationErrors);
            }

            return sanitizeCharsToHtmlEscapedChars(css);
        }

        private static void validateCss(String css, List<String> validationErrors) {
            final String cssStriped = css.trim();

            final Matcher validCss = completeCssPattern.matcher(cssStriped);

            if (!validCss.matches() && cssStriped.length() > 0) {
                validationErrors.add("CSS in style-element is invalid.");
            }

            Matcher selectorAndContent = selectorAndContentPattern.matcher(cssStriped);

            while (selectorAndContent.find()) {

                final String selector = selectorAndContent.group(1).trim();
                final String selectorContent = selectorAndContent.group(2).trim();
                log.debug("Parsing selectorContent for selector {}", selector);

                if (selector.length() == 0) {
                    log.warn("Could not match css-selector, but regex matched anyways. Something might be wrong with the regex. Style-element content: {}", cssStriped);
                    validationErrors.add("CSS selector not found. Indicates illegal css.");
                } else if (containsBlacklistedWord(selectorContent)) {
                    validationErrors.add("Content of selector '" + selector + "' contains one or more illegal words.");
                } else {
                    validateDeclarations(selectorContent, validationErrors);
                }
            }
        }

        private static boolean containsBlacklistedWord(String content) {
            final String contentLowerCase = content.toLowerCase();
            return WORDS_IN_VALUE_BLACKLIST.stream()
                .anyMatch(blacklistedWord -> contentLowerCase.contains(blacklistedWord.toLowerCase()));
        }

        private static void validateDeclarations(String selectorContent, List<String> validationErrors) {

            final String stripedContent = selectorContent.trim();
            Matcher declaration = propertyValuePattern.matcher(stripedContent);

            //The alternative to this boolean is to make a new pattern that matches the whole selectorContent (concluded that it was more error prone)
            boolean matcherDidNotFindDeclaration = true;

            while (declaration.find()) {
                matcherDidNotFindDeclaration = false;
                final String property = declaration.group(1).trim();
                final String value = declaration.group(2).trim();
                log.debug("Processing declaration:  {}: {}", property, value);


                if (CSS_PROPERTY_WHITELIST.containsKey(property)) {
                    boolean isNotOK = !CSS_PROPERTY_WHITELIST.get(property).test(value.toLowerCase());
                    if (isNotOK) {
                        log.warn("Value '{}' is not allowed for property '{}'.", value, property);
                        validationErrors.add("Value '" + value + "' is not allowed for property '" + property + "'.");
                    }
                } else {
                    log.debug("Property '{}' is not allowed in style-element", property);
                    validationErrors.add("Property '" + property + "' is not allowed.");
                }
            }

            if (matcherDidNotFindDeclaration && stripedContent.length() > 0) {
                if (!stripedContent.endsWith(";")) {
                    validationErrors.add("Declaration must end with ';'.");
                } else {
                    log.warn("Found no match in property and value regex, even though it should. Something might be wrong with the regex. Content: {}", stripedContent);
                    validationErrors.add("Malformed declaration: " + stripedContent + " .");
                }
            }
        }

        private static String sanitizeCharsToHtmlEscapedChars(String css) {
            String escapedStyleContent = css;
            for (Map.Entry<String, String> charAndEscaped : HTML_ESCAPE_CHARS.entrySet()) {
                String character = charAndEscaped.getKey();
                String escapedChar = charAndEscaped.getValue();
                escapedStyleContent = escapedStyleContent.replace(character, escapedChar);
            }
            return escapedStyleContent;
        }

        @Override
        public void openDocument() {
            receiver.openDocument();
            inStyleTag = false;
        }

        @Override
        public void closeDocument() {
            receiver.closeDocument();
        }

        @Override
        public void openTag(String elementName, List<String> attrs) {
            receiver.openTag(elementName, attrs);
            inStyleTag = STYLE_TAG.equals(elementName);
        }

        @Override
        public void closeTag(String elementName) {
            receiver.closeTag(elementName);
            inStyleTag = false;
        }

        @Override
        public void text(String text) {
            if (inStyleTag) {
                receiver.text(validateAndSanitizeCss(text));
            } else {
                receiver.text(text);
            }
        }
    }

}
