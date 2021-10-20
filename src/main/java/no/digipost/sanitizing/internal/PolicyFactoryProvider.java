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

import org.owasp.html.PolicyFactory;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public final class PolicyFactoryProvider {

    private PolicyFactoryProvider() {}

    public static final Instant V2_IN_EFFECT = ZonedDateTime.of(2019, 6,4,7,10,0,0, ZoneOffset.UTC).toInstant();

    /**
     *
     * @return the current PolicyFactory used by digipost
     */
    public static PolicyFactory getPolicyFactory(){
        return getPolicyFactory(Instant.now());
    }

    public static PolicyFactory getPolicyFactory(Instant documentCreationDate){
        if(documentCreationDate.isBefore(V2_IN_EFFECT)) {
            return ApiHtmlValidatorPolicy.V1_VALIDATE_ONLY_HTML_POLICY;
        }else {
            return ApiHtmlValidatorPolicy.V2_VALIDATE_HTML_AND_CSS_POLICY;
        }
    }

    public static ErrorCollectingHtmlChangeListener errorCollector() {
        return new ErrorCollectingHtmlChangeListener();
    }
}
