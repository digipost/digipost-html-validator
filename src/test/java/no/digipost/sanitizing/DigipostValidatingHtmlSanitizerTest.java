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

import no.digipost.sanitizing.exception.CSSValidationException;
import no.digipost.sanitizing.exception.HTMLValidationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DigipostValidatingHtmlSanitizerTest {

    private PrintStream old;
    private ByteArrayOutputStream systout;

    @BeforeEach
    void setUp() {
        systout = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(systout);
        old = System.out;
        System.setOut(ps);
    }

    @Test
    void should_sanitize_html() {
        DigipostValidatingHtmlSanitizer.main(new String[]{
            "<html><head><!--script>alert('per');</script--><body><h1>Hello World!</h1></body></html>"
        });

        assertThat(systout.toString(), allOf(
            not(equalTo("")),
            not(containsString("script"))
        ));
    }

    @Test
    void should_fail_validation_html() {
        HTMLValidationException thrown =
            assertThrows(HTMLValidationException.class,
                () -> DigipostValidatingHtmlSanitizer.main(new String[]{
                    "<html><head><script>alert('per');</script><body><h1>Hello World!</h1></body></html>"
                }),
                "Expected main() to throw, but it didn't");

        assertThat(thrown.getValidationErrors().get(0), equalTo("Found HTML policy violation. Tag name: script"));
    }

    @Test
    void should_fail_validation_css() {
        CSSValidationException thrown =
            assertThrows(CSSValidationException.class,
                () -> DigipostValidatingHtmlSanitizer.main(new String[]{
                    "<html><head><style>@media print {} </style><body><h1>Hello World!</h1></body></html>"
                }),
                "Expected main() to throw, but it didn't");

        assertThat(thrown.getValidationErrors().get(0), equalTo("CSS in style-element is invalid."));
    }

    @Test
    void should_fail_script_inside_style_element() {
        // Test for CVE_2021_42575
        CSSValidationException thrown =
            assertThrows(CSSValidationException.class,
                () -> DigipostValidatingHtmlSanitizer.main(new String[]{
                    "<select><option><style><script>alert(1)</script></style></option></select>"
                }),
                "Expected main() to throw, but it didn't");

        assertThat(thrown.getValidationErrors().get(0), equalTo("CSS in style-element is invalid."));
    }

    @AfterEach
    void tearDown() {
        System.setOut(old);
    }
}
