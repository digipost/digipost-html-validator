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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlValidatorTest {

    @Test
    void enkle_tilfeller_skal_være_helt_ok() {
        final HtmlValidationResult valider = new HtmlValidator().valider("<html></html>".getBytes());

        assertTrue(valider.okForWeb);
        assertSame(valider, HtmlValidationResult.HTML_EVERYTHING_OK);
    }

    @Test
    void ikke_avsluttet_tag_skal_avsluttes() {
        final HtmlValidationResult valider = new HtmlValidator().valider("<html><body></html>".getBytes());

        assertTrue(valider.okForWeb);
        assertEquals(valider.toString(), "[ HtmlValidationResult OK for web\n" +
            "<html><body></body></html>]");
    }

    @Test
    void lenker_skal_få_rel_target() {
        final HtmlValidationResult valider = new HtmlValidator().valider(("<!doctype html>\n" +
            "<html lang=\"no\">\n" +
            "<head>\n" +
            "    <meta charset=\"utf-8\">\n" +
            "    <title>Posten Digipost</title>\n" +
            "</head>\n" +
            "<body id=\"Digipost\">\n" +
            "<h1>Digipost</h1>\n" +
            "</body>\n" +
            "</html>\n").getBytes());

        assertTrue(valider.okForWeb);
        assertEquals(valider.toString(), "[ HtmlValidationResult OK for web\n" +
            "<!doctype html>\n" +
            "<html lang=\"no\"><head><meta charset=\"utf-8\" /><title>Posten Digipost</title></head><body id=\"Digipost\">\n" +
            "<h1>Digipost</h1>\n" +
            "</body></html>\n" +
            "]");
    }

    @Test
    void javascript_skal_kaste_exception() {
        final HtmlValidationResult valider = new HtmlValidator().valider("<html><body><script/></body></html>".getBytes());

        assertFalse(valider.okForWeb);
        assertEquals(valider.toString(), "[ HtmlValidationResult\n" +
            "Found HTML policy violation. Tag name: script]");
    }

    @Test
    void gal_css_skal_kaste_exception() {
        final HtmlValidationResult valider = new HtmlValidator().valider("<html><body><style>*   {color:red;}</style></body></html>".getBytes());

        assertFalse(valider.okForWeb);
        assertEquals(valider.toString(), "[ HtmlValidationResult\n" +
            "CSS in style-element is invalid., CSS selector not found. Indicates illegal css.]");
    }

    @Test
    void ulovlig_css_skal_kaste_exception() {
        final HtmlValidationResult valider = new HtmlValidator().valider("<html><body><style>.per{display:none;}</style></body></html>".getBytes());

        assertFalse(valider.okForWeb);
        assertEquals(valider.toString(), "[ HtmlValidationResult\n" +
            "Value 'none' is not allowed for property 'display'.]");
    }
}
