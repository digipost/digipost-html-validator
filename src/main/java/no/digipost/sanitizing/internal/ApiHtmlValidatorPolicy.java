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

import org.owasp.html.AttributePolicy;
import org.owasp.html.CssSchema;
import org.owasp.html.ElementPolicy;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static no.digipost.sanitizing.internal.ValidatorPatterns.ALIGN;
import static no.digipost.sanitizing.internal.ValidatorPatterns.COLOR_NAME_OR_COLOR_CODE;
import static no.digipost.sanitizing.internal.ValidatorPatterns.CSS_TYPE;
import static no.digipost.sanitizing.internal.ValidatorPatterns.DIMENSION;
import static no.digipost.sanitizing.internal.ValidatorPatterns.FLEX_BASIS;
import static no.digipost.sanitizing.internal.ValidatorPatterns.HTML_CLASS;
import static no.digipost.sanitizing.internal.ValidatorPatterns.HTML_ID;
import static no.digipost.sanitizing.internal.ValidatorPatterns.HTML_TITLE;
import static no.digipost.sanitizing.internal.ValidatorPatterns.IMAGE_DATA_URL;
import static no.digipost.sanitizing.internal.ValidatorPatterns.META_VIEWPORT_VALUES;
import static no.digipost.sanitizing.internal.ValidatorPatterns.NAME;
import static no.digipost.sanitizing.internal.ValidatorPatterns.NUMBER;
import static no.digipost.sanitizing.internal.ValidatorPatterns.NUMBER_OR_PERCENT;
import static no.digipost.sanitizing.internal.ValidatorPatterns.ONE_CHAR;
import static no.digipost.sanitizing.internal.ValidatorPatterns.ONSITE_OR_OFFSITE_URL;
import static no.digipost.sanitizing.internal.ValidatorPatterns.ONSITE_URL;
import static no.digipost.sanitizing.internal.ValidatorPatterns.PARAGRAPH;
import static no.digipost.sanitizing.internal.ValidatorPatterns.TARGET_BLANK;
import static no.digipost.sanitizing.internal.ValidatorPatterns.TYPE_AND_CHARSET;
import static no.digipost.sanitizing.internal.ValidatorPatterns.VALIGN;

/**
 * OWASP HTML Sanitizer Policy based on the example EBAY policy at
 * https://github.com/OWASP/java-html-sanitizer/blob/master/src/main/java/org/owasp/html/examples/EbayPolicyExample.java.
 * <p>
 * We've done formatting changes and some adjustments, so it can be hard to trace the policy back to the original,
 * but that's where it's from anyway.
 * <p>
 * It's made to allow everything that was allowed in our old AnitSamy policy, except the bypass flaws, obviously.
 *
 * <p>
 * Ooo, how to test these policies efficiently? No problem, head over to HtmlSanitizerBrowserTestBed and you're good to go.
 * If you are able to trigger a JavaScript alert box in the HTML popup you've won!
 *
 */
final class ApiHtmlValidatorPolicy {
    private static final Set<String> CSS_WHITELIST;
    static final Map<String, Predicate<String>> CSS_PROPERTY_WHITELIST;
    private static final String[] KITH_TAGS = {"abbr", "acronym", "address", "dfn", "kbd", "q", "var", "tt", "caption"};

    static {
        HashSet<String> defaultProperties = new HashSet<>(CssSchema.DEFAULT.allowedProperties());
        defaultProperties.add("top");
        defaultProperties.add("bottom");
        defaultProperties.add("left");
        defaultProperties.add("right");
        defaultProperties.add("background");
        defaultProperties.add("page-break-before");
        defaultProperties.add("page-break-after");
        defaultProperties.add("page-break-inside");
        CSS_WHITELIST = Collections.unmodifiableSet(defaultProperties);

        final Predicate<String> allowAllValuesPredicate = (value) -> true;
        final Map<String, Predicate<String>> propertyValueWhitelist = CSS_WHITELIST.stream().collect(Collectors.toMap(prop -> prop, prop -> allowAllValuesPredicate));
        propertyValueWhitelist.put("clear", allowAllValuesPredicate);
        propertyValueWhitelist.put("float", allowAllValuesPredicate);
        propertyValueWhitelist.put("display", value -> value.equals("block") || value.equals("inline-block") || value.equals("inline") || value.equals("flex"));
        propertyValueWhitelist.put("content", allowAllValuesPredicate);
        propertyValueWhitelist.put("flex-direction", value -> value.equals("row") || value.equals("column") || value.equals("row-reverse") || value.equals("column-reverse"));
        propertyValueWhitelist.put("flex-wrap", value -> value.equals("nowrap") || value.equals("wrap") || value.equals("wrap-reverse"));
        propertyValueWhitelist.put("justify-content", value -> value.equals("flex-start") || value.equals("flex-end") || value.equals("center") || value.equals("space-between") || value.equals("space-around") || value.equals("space-evenly"));
        propertyValueWhitelist.put("align-items", value -> value.equals("flex-start") || value.equals("flex-end") || value.equals("center") || value.equals("baseline") || value.equals("stretch"));
        propertyValueWhitelist.put("align-self", value -> value.equals("auto") || value.equals("flex-start") || value.equals("flex-end") || value.equals("center") || value.equals("baseline") || value.equals("stretch"));
        propertyValueWhitelist.put("gap", value -> DIMENSION.matcher(value).matches());
        propertyValueWhitelist.put("flex", ApiHtmlValidatorPolicy::validateFlexProperty);

        CSS_PROPERTY_WHITELIST = Collections.unmodifiableMap(propertyValueWhitelist);
    }

    private static boolean validateFlexProperty(String value) {
        String[] values = value.split("\\s+");
        if (values.length < 1 || values.length > 3) {
            return false;
        }
        boolean hasValidFlexGrowValue = NUMBER.matcher(values[0]).matches();
        boolean hasValidFlexShrinkValue = values.length < 2 || NUMBER.matcher(values[1]).matches();
        boolean hasValidFlexBasisValue = values.length < 3 || FLEX_BASIS.matcher(values[2]).matches();

        return hasValidFlexGrowValue && hasValidFlexShrinkValue && hasValidFlexBasisValue;
    }

    // Version 1 of policy. We used this policy before we introduced CSS-validation/-sanitation
    static final PolicyFactory V1_VALIDATE_ONLY_HTML_POLICY = new HtmlPolicyBuilder()
        .allowStyling(CssSchema.withProperties(CSS_WHITELIST))
        .allowUrlsInStyles(AttributePolicy.IDENTITY_ATTRIBUTE_POLICY)
        .allowStandardUrlProtocols().allowUrlProtocols("data")

        // Global attribute definitions
        .allowAttributes("id").matching(HTML_ID).globally()
        .allowAttributes("class").matching(HTML_CLASS).globally()
        .allowAttributes("lang").matching(Pattern.compile("[a-zA-Z]{2,20}")).globally()
        .allowAttributes("title").matching(HTML_TITLE).globally()

        .allowAttributes("align").matching(ALIGN).onElements("p")

        .allowAttributes("for").matching(HTML_ID).onElements("label")

        .allowAttributes("color").matching(COLOR_NAME_OR_COLOR_CODE::test).onElements("font")
        .allowAttributes("face").matching(Pattern.compile("[\\w;, \\-]+")).onElements("font")
        .allowAttributes("size").matching(NUMBER).onElements("font")

        .allowElements(addingAttributeIfMissing("target", "_blank"), "a")
        .allowAttributes("target").matching(value("_blank")).onElements("a")
        .allowAttributes("href").matching(ONSITE_OR_OFFSITE_URL::test).onElements("a")
        .allowAttributes("nohref").onElements("a")
        .allowAttributes("name").matching(NAME).onElements("a")
        .requireRelNofollowOnLinks()
        .requireRelsOnLinks("noreferrer", "noopener") // Prevent target link page from being able to communicate with ours (https://www.jitbit.com/alexblog/256-targetblank---the-most-underestimated-vulnerability-ever/)

        .allowAttributes("src").matching(IMAGE_DATA_URL).onElements("img")
        .allowAttributes("alt").onElements("img")

        .allowAttributes("border", "cellpadding", "cellspacing").matching(NUMBER).onElements("table")
        .allowAttributes("bgcolor").matching(COLOR_NAME_OR_COLOR_CODE::test).onElements("table")
        .allowAttributes("background").matching(ONSITE_URL).onElements("table")
        .allowAttributes("align").matching(ALIGN).onElements("table")
        .allowAttributes("noresize").matching(Pattern.compile("(?i)noresize")).onElements("table")

        .allowAttributes("background").matching(ONSITE_URL).onElements("td", "th", "tr")
        .allowAttributes("bgcolor").matching(COLOR_NAME_OR_COLOR_CODE::test).onElements("td", "th")
        .allowAttributes("abbr").matching(PARAGRAPH).onElements("td", "th")
        .allowAttributes("axis", "headers").matching(NAME).onElements("td", "th")
        .allowAttributes("scope").matching(Pattern.compile("(?i)(?:row|col)(?:group)?")).onElements("td", "th")
        .allowAttributes("nowrap").onElements("td", "th")

        .allowAttributes("height", "width").matching(NUMBER_OR_PERCENT).onElements("table", "td", "th", "tr", "img", "hr")
        .allowAttributes("align").matching(ALIGN).onElements("thead", "tbody", "tfoot", "img", "td", "th", "tr", "colgroup", "col", "hr")
        .allowAttributes("valign").matching(VALIGN).onElements("thead", "tbody", "tfoot", "td", "th", "tr", "colgroup", "col")
        .allowAttributes("charoff").matching(NUMBER_OR_PERCENT).onElements("td", "th", "tr", "colgroup", "col", "thead", "tbody", "tfoot")
        .allowAttributes("char").matching(ONE_CHAR).onElements("td", "th", "tr", "colgroup", "col", "thead", "tbody", "tfoot")
        .allowAttributes("colspan", "rowspan").matching(NUMBER).onElements("td", "th")
        .allowAttributes("span", "width").matching(NUMBER_OR_PERCENT).onElements("colgroup", "col")

        .allowAttributes("type").matching(CSS_TYPE).onElements("style")
        .allowAttributes("target").matching(TARGET_BLANK).onElements("base")

        .allowAttributes("http-equiv").matching(true, "content-type").onElements("meta")
        .allowAttributes("charset").onElements("meta")
        .allowAttributes("name").matching(true, "viewport").onElements("meta")
        .allowAttributes("content").matching(oneOf(META_VIEWPORT_VALUES, TYPE_AND_CHARSET)).onElements("meta")

        .allowElements(KITH_TAGS)
        .allowElements(
            "html", "body", "head", "title", "meta", "base", "style",
            "a", "label", "noscript", "h1", "h2", "h3", "h4", "h5", "h6",
            "p", "i", "b", "u", "strong", "em", "small", "big", "pre", "code",
            "cite", "samp", "sub", "sup", "strike", "center", "blockquote",
            "hr", "br", "col", "font", "map", "span", "div", "img",
            "ul", "ol", "li", "dd", "dt", "dl", "tbody", "thead", "tfoot",
            "table", "td", "th", "tr", "colgroup", "fieldset", "legend",
            "figure", "figcaption", "header", "nav", "section", "aside",
            "article", "footer", "hgroup", "main"
        )


        // Spans without attributes are usually stripped (because they semantically are the same as just the span contents).
        // Stripping of elements look like validation errors to us, so we'll rather keep them - even when they're empty.
        .allowWithoutAttributes("span")
        .toFactory();


    static final PolicyFactory V2_VALIDATE_HTML_AND_CSS_POLICY = V1_VALIDATE_ONLY_HTML_POLICY.and(new HtmlPolicyBuilder()
            .allowTextIn("style")
            .withPreprocessor(new StyleElementPreprocessor())
            .toFactory());



    private static AttributePolicy value(final String mustHaveValue) {
        return (elementName, attributeName, value) -> {
            if (value.equals(mustHaveValue)) {
                return value;
            }

            return null;
        };
    }

    private static AttributePolicy oneOf(final Pattern... patterns) {
        return (elementName, attributeName, value) -> {
            Optional<Pattern> match = Arrays.stream(patterns).filter(pattern -> pattern.matcher(value).matches()).findFirst();

            return match.isPresent() ? value : null;
        };
    }

    private static ElementPolicy addingAttributeIfMissing(final String attribute, final String value) {
        return ((elementName, attributes) -> {
            int indexOfAttribute = attributes.indexOf(attribute);
            if (indexOfAttribute == -1) {
                attributes.add(attribute);
                attributes.add(value);
            }

            return elementName;
        });
    }

}
