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
package no.digipost.sanitizing;

import no.digipost.sanitizing.exception.ValidationException;

import java.util.Collections;
import java.util.List;

public class HtmlValidationResult {
    public static final HtmlValidationResult HTML_EVERYTHING_OK = new HtmlValidationResult(true, false);

    public final boolean okForWeb;
    public final boolean hasDiffAfterSanitizing;
    private final List<String> validationErrors;
    private final String output;

    public HtmlValidationResult(boolean okForWeb, boolean hasDiffAfterSanitizing) {
        this.okForWeb = okForWeb;
        this.hasDiffAfterSanitizing = hasDiffAfterSanitizing;
        this.validationErrors = Collections.emptyList();
        this.output = "";
    }

    public HtmlValidationResult(ValidationException e) {
        this.okForWeb = false;
        this.hasDiffAfterSanitizing = false;
        this.validationErrors = e.getValidationErrors();
        this.output = "";
    }

    public HtmlValidationResult(String output) {
        this.output = output;
        this.okForWeb = true;
        this.validationErrors = Collections.emptyList();
        this.hasDiffAfterSanitizing = true;
    }

    @Override
    public String toString() {
        return "[ " + getClass().getSimpleName() + ((this.okForWeb) ? " OK for web" : "") + "\n" + String.join(", ", validationErrors) + String.join("\n", this.output) + "]";
    }
}
