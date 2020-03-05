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

import no.digipost.sanitizing.DigipostValidatingHtmlSanitizer;
import no.digipost.sanitizing.exception.ValidationException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class RichHtmlValidatorTest {

    private static final String HTML_IMG_BASE64_DATAURL = "<img src=\"data:image/png;base64,"
        + "iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxg"
        + "ljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==\" alt=\"Red dot\">";

    private static final String HTML_MACFARSI = "<html><head><meta http-equiv=\"Content-Type\""
        + " content=\"text/html;charset=x-mac-farsi\"></head><body>Hei</body></html>";

    private static final String HTML_ISO88591 = "<html><head><meta http-equiv=\"Content-Type\""
        + " content=\"text/html;charset=iso-8859-1\"></head><body>Hei</body></html>";

    private static final String HTML_UTF8 = "<html><head><meta http-equiv=\"Content-Type\""
        + "content=\"text/html;charset=utf8\"></head><body>Hei</body></html>";

    private static final String[] KITH_TAGS = {"abbr", "acronym", "address", "blockquote", "br", "cite", "code", "dfn", "div", "em", "h1",
        "h2", "h3", "h4", "h5", "h6", "kbd", "p", "pre", "q", "samp", "span", "strong", "var", "dl", "dt", "dd", "ol", "ul", "li", "b",
        "big", "hr", "i", "small", "sub", "sup", "tt", "caption", "caption", "table", "td", "th", "tr"};

    private final DigipostValidatingHtmlSanitizer validator = new DigipostValidatingHtmlSanitizer();

    @Test
    public void smoketest_skal_detektere_script() {
        assertInvalid("<script>alert(1)</script>");
    }

    @Test
    public void skal_stoette_meta_content_type_utf8() {
        assertValid(HTML_UTF8);
    }

    @Test
    public void skal_stoette_meta_content_type_iso88591() {
        assertValid(HTML_ISO88591);
    }

    @Test
    public void skal_ikke_stoette_meta_content_type_annet_enn_iso8859og_utf8() {
        assertInvalid(HTML_MACFARSI);
    }

    @Test
    public void should_preserve_doctype_html() {
        String validatedHtml = validator.sanitize("<!DOCTYPE html><div><p>Content</p></div>", PolicyFactoryProvider.getPolicyFactory());
        assertEquals("<!doctype html><div><p>Content</p></div>", validatedHtml);
    }

    @Test
    public void smoketest_slippe_gjennom_vanlig_tekst_med_strong() {
        assertValid("<b>Hallo på rei</b>");
    }

    @Test
    public void smoketest_slippe_gjennom_full_html() {
        assertValid("<html><head></head><body><b>Hallo på rei</b></body></html>");
    }

    @Test
    public void skal_slippe_gjennom_style_definisjon() {
        assertValid("<style>h1 { font-size: 110%; }</style><h1>Heisann</h1><b>Hallo på rei</b></body></html>");
    }

    @Test
    public void skal_slippe_gjennom_bilder_i_data_urler() {
        assertValid(HTML_IMG_BASE64_DATAURL);
    }

    @Test
    public void skal_ikke_slippe_gjennom_eksterne_bilder() {
        assertInvalid("<img src=\"http://evil.com/angryrabbit.jpg\" alt=\"Red dot\">");
    }

    @Test
    public void skal_slippe_gjennom_tomme_span_uten_attributter() {
        assertValid("<span>Dette er bare en uskyldig liten span!</span>");
    }

    @Test
    public void skal_ikke_slippe_gjennom_bilde_med_javascript() {
        assertInvalid("<img src=\"javascript:alert(1337)\"/>");
    }

    @Test
    public void skal_stoette_alle_kith_tags() {
        for (String s : KITH_TAGS) {
            assertValid(s);
        }
    }

    @Test
    public void skal_godta_multiline_base64_img() {
        assertValid("<img src=\"data:image/gif;base64,vQfAXABpgE7A1+k6Jg4E7gLwFYCzBJxh6HRDvn84TBzVAZOdBTZnA088D3UJcFc1jHnWFGzz6ECMbkIFfMEMVSEyqg/pGDS3Dm6Cz2r\n" +
            "\t\t\t3wqspOIUhABGCmdMkzdChecH8QSDQX/KJ9gECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBPgL878A4WaOAl4wRWUAAAAASUVORK\n" +
            "\t\t\t5CYII=\" />");
    }

    @Test
    public void smoke_test_skal_ikke_slippe_gjennom_inline_svg() {
        assertInvalid("<div><svg onclick=alert('evil')></svg></div>");
    }

    @Test
    public void skal_godta_tom_style() {
        assertValid("<html><head><style></style></head><body>Tjallabais</body></html>");
    }

    @Test
    public void skal_ikke_akseptere_ond_attributt_paa_style() {
        assertInvalid("<html><head><style onload=\"alert(1)\">body {}</style></head><body>Tjallabais</body></html>");
    }

    @Test
    public void skal_tillate_data_url_for_backgound() {
        assertValid("<div style=\"background:url(data:image/jpeg;base64,/9j=)\">Hei</div>");
    }

    @Test
    public void skal_tillate_tom_td() {
        assertValid("<table><tr><td>asdf</td><td>dsfg</td></tr><tr><td colspan='2'>&nbsp;</td></tr></table>");
    }

    @Test
    public void skal_tillate_tom_title() {
        assertValid("<html><head><title></title></head><body>asdf</body></html>");
    }

    @Test
    public void skal_tillate_base_target_blank() {
        assertValid("<html><head><base target=\"_blank\"/></head><body>asdf</body></html>");
    }

    @Test
    public void skal_ikke_tillate_andre_base_targets_enn_blank() {
        assertInvalid("<html><head><base target=\"_top\"/></head><body>asdf</body></html>");
    }

    @Test
    public void skal_ikke_tillate_base_href() {
        try {
            validator.sanitize("<html><head><base target=\"_blank\" href=\"http://www.evil.com/\"/></head><body>asdf</body></html>", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
            fail("Should fail");
        } catch (ValidationException dae) {
            assertEquals("Found HTML policy violation: Tag name: base, attribute(s): href", dae.getValidationErrors().get(0));
        }
    }


    @Test
    public void skal_tillate_et_begrenset_sett_metaattributter() {
        validator.sanitize("<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\">", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
        validator.sanitize("<meta http-equiv=\"content-type\" content=\"text/html;charset=UTF-8\">", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
        validator.sanitize("<meta name=\"viewport\" content=\"user-scalable = yes\">", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
    }

    @Test
    public void skal_ikke_tillate_andre_metaattributter() {
        assertInvalid("<meta http-equiv=\"Something-Else\" content=\"hallo\">");
        assertInvalid("<meta name=\"viewport\" content=\"something-random = no\">");
    }

    @Test
    public void skal_tillate_maillenker_uten_target_blank() {
        validator.sanitize("<a href=\"mailto:hei@example.org\">Klikk for mail</a>", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
    }

    @Test
    public void skal_bruke_target_blank_på_lenker_ved_andre_targets() {
        String validatedHtml = validator.sanitize("<a href=\"http://example.org\" target=\"_self\">Clicky clicky</a>", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
        assertEquals("<a href=\"http://example.org\" target=\"_blank\" rel=\"nofollow noreferrer noopener\">Clicky clicky</a>", validatedHtml);
    }

    @Test
    public void skal_legge_på_target_blank_ved_manglende_target() {
        String validatedHtml = validator.sanitize("<a href=\"http://example.org\">Clicky clicky</a>", ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
        assertEquals("<a href=\"http://example.org\" target=\"_blank\" rel=\"nofollow noreferrer noopener\">Clicky clicky</a>", validatedHtml);
    }

    private void assertValid(String html) {
        try {
            validator.sanitize(html, ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
        } catch (ValidationException dae) {
            if (!dae.getValidationErrors().isEmpty()) {
                fail("Should be valid html, but failed due to " + dae.getMessage());
            }
            throw dae;
        }
    }

    private void assertInvalid(String html) {
        try {
            validator.sanitize(html, ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY);
            fail("Should fail");
        } catch (ValidationException dae) {
            if (dae.getValidationErrors().isEmpty()) {
                throw dae;
            }
            // Ahhh yee! Got valideringsfeil!
        }
    }
}
