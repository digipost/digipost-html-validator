/*
 * Copyright (C) Posten Norge AS
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package no.digipost.sanitizing.internal;

import no.digipost.sanitizing.DigipostValidatingHtmlSanitizer;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileOutputStream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class HtmlSanitizerBrowserTestBed {

    private static DigipostValidatingHtmlSanitizer validatingHtmlSanitizer = new DigipostValidatingHtmlSanitizer();

    public static void main(String[] args) throws Exception {
        String html = IOUtils.toString(HtmlSanitizerBrowserTestBed.class.getResourceAsStream("testInput.html"), UTF_8);

        String sanitizedHtml = validatingHtmlSanitizer.sanitize(html, ApiHtmlValidatorPolicy.ALLOW_STYLE_ELEMENT_POLICY);

        File htmlFile = File.createTempFile("sanitizer-test", "html");
        IOUtils.write(sanitizedHtml, new FileOutputStream(htmlFile), UTF_8);

        Runtime.getRuntime().exec(new String[]{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--kiosk", htmlFile.getAbsolutePath()});

        System.out.println("Sjekk Chrome, der har du HTMLen din!");
    }

}
