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

import org.owasp.html.HtmlChangeListener;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.util.stream.Collectors.joining;

final public class ErrorCollectingHtmlChangeListener implements HtmlChangeListener<List<String>> {

	private final List<String> errorCollector;

	ErrorCollectingHtmlChangeListener() {
		this.errorCollector = new ArrayList<>();
	}

	@Override
	public void discardedTag(List<String> context, String elementName) {
		errorCollector.add("Found HTML policy violation. Tag name: " + elementName);
	}

	@Override
	public void discardedAttributes(List<String> context, String tagName, String... attributeNames) {
		String illegalAttributes = Arrays.stream(attributeNames).collect(joining(", "));
		errorCollector.add("Found HTML policy violation: Tag name: " + tagName + ", attribute(s): " + illegalAttributes);
	}

	public boolean hasErrors() {
		return !errorCollector.isEmpty();
	}


	public int getNumberOfErrors() {
		return errorCollector.size();
	}

	public List<String> getErrors() {
		return this.errorCollector;
	}
}
