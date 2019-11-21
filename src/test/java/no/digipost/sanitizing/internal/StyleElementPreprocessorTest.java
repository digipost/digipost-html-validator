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

import no.digipost.sanitizing.exception.CSSValidationException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static co.unruly.matchers.Java8Matchers.where;
import static no.digipost.sanitizing.internal.StyleElementPreprocessor.StyleElementReceiver.validateAndSanitizeCss;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

public class StyleElementPreprocessorTest {

	@Test
	public void valid_css() {
		String styleContent = ".myClass table td {\n" +
			"height: 40px;\n" +
			"border: solid 2px black;\n" +
			"text-align: center;\n" +
			"}\n" +
			".infoText div.subHeader {\n" +
			"margin: 30px 0px;\n" +
			"}";

		String actual = validateAndSanitizeCss(styleContent);
		assertThat(actual, is(styleContent));
	}

	@Test
	public void valid_css_with_comma() {
		String styleContent = ".myClass table td {\n" +
			"font-family: Arial, Helvetica, sans-serif;\n" +
			"}";

		String actual = validateAndSanitizeCss(styleContent);
		assertThat(actual, is(styleContent));
	}

	@Test
	public void value_with_parentheses_is_valid() {
		String styleContent = ".content--green {\n" +
			"       background-color: rgba(69,164,170,0.12);\n" +
			"       page-break-before: always;\n" +
			"}";
		String actual = validateAndSanitizeCss(styleContent);
		assertThat(actual, is(styleContent));
	}

	@Test
	public void at_media_is_not_allowed() {
		String styleContent = "@media print {\n" +
			"  pre, blockquote {margin: 30px 0px;}\n" +
			"}";
		try {
			validateAndSanitizeCss(styleContent);
            fail();
		} catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
		}
	}

	@Test
	public void comment_of_selector_is_not_allowed() {
		String styleContent = ".myClass table td {\n" +
			"height: 40px;\n" +
			"border: solid 2px black;\n" +
			"text-align: center;\n" +
			"}\n" +
			"/* .infoText div.subHeader {\n" +
			"margin: 30px 0px;\n" +
			"} */";
		try{
			validateAndSanitizeCss(styleContent);
			fail();
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
		}
	}

	@Test
	public void comment_of_declaration_is_not_allowed() {
		String styleContent = ".myClass table td {\n" +
			"height: 40px;\n" +
			"border: solid 2px black;\n" +
			"text-align: center;\n" +
			"}\n" +
			".infoText div.subHeader {\n" +
			"/* margin: 30px 0px; */ \n" +
			"}";
		try{
			validateAndSanitizeCss(styleContent);
			fail();
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
		}
	}

	@Test
	public void multiline_css_with_not_allowed_prop() {
		String styleContent = ".myClass table td {\n" +
			"not-a-prop: 40px;\n" +
			"}\n" +
			".infoText div.subHeader {\n" +
			"margin: 30px 0px;\n" +
			"}";

		try{
			validateAndSanitizeCss(styleContent);
			fail();
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
			assertThat(exp.getValidationErrors().get(0), containsString("Property 'not-a-prop' is not allowed."));
		}
	}

	@Test
	public void css_should_produce_multiple_validation_errors() {
		String styleContent = ".myClass table td {\n" +
			"not-a-prop: 40px;\n" +
			"}\n" +
			".infoText div.subHeader {\n" +
			"margin: javascript::alert('hello');\n" +
			"} invalid css";

		try{
			validateAndSanitizeCss(styleContent);
			fail();
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(3)));
		}
	}

	@Test
	public void invalid_css_with_illegal_chars_should_fail() {
		String styleContent = "This is not \\\\{ `css` at al%l  &lt;script&gt;alert('hello') }&lt;/script&gt; , just garbage javascript:alert('xss')";

		try{
			validateAndSanitizeCss(styleContent);
			fail("Should fail due to invalid css");
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
			assertThat(exp.getValidationErrors().get(0), containsString("CSS in style-element is invalid."));
		}
	}

	@Test
	public void invalid_css_should_fail() {
		String styleContent = "This is not { css at all; } just garbage javascript:alert('xss')";

		try{
			validateAndSanitizeCss(styleContent);
			fail("Should fail due to invalid css");
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(2)));
			assertThat(exp.getValidationErrors().get(0), containsString("CSS in style-element is invalid."));
		}
	}

	@Test
	public void multi_line_selector_should_fail() {
		String styleContent = "#myId li::before,\n .className {" +
			"height: 40px;" +
			"border: solid 2px black;" +
			"text-align: center;" +
			"}" +
			".infoText div.subHeader {" +
			"margin: 30px 0px;" +
			"}";


		String actual = validateAndSanitizeCss(styleContent);
		assertThat(actual, is(styleContent));
	}

	@Test
	public void simple_attribute_selector_is_ok() {
		String styleContent = "#myId[href] { height: 40px; }";

		String actual = validateAndSanitizeCss(styleContent);

		assertThat(actual, is(styleContent));
	}

	@Test
	public void complex_attribute_selector_should_fail() {
		String styleContent = "#myId[href*=\"example\"] { height: 40px; }";

		try{
			validateAndSanitizeCss(styleContent);
			fail();
		}  catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
			assertThat(exp.getValidationErrors().get(0), containsString("CSS in style-element is invalid."));
		}
	}

	@Test
	public void css_on_one_line_is_valid() {
		String styleContent = "#myId li::before, .className {" +
			"height: 40px;" +
			"border: solid 2px black;" +
			"text-align: center;" +
			"}" +
			".infoText div.subHeader {" +
			"margin: 30px 0px;" +
			"}";

		String actual = validateAndSanitizeCss(styleContent);

		assertThat(actual, is(styleContent));
	}

	@Test
	public void should_html_encode() {
		String styleContent = ".electionInfoText ul li::before {\n" +
			" content: \"\\2022/\";\n" +
			" content: \'\\2022<\';\n" +
			" font-size: 10px;" +
			"}";

		final String actual = validateAndSanitizeCss(styleContent);

		assertThat(actual, containsString("&#x2F;"));
		assertThat(actual, containsString("&lt"));
	}

	@Test
	public void fail_on_not_allowed_prop() {
		String styleContent = ".myClass table td {\n" +
			"notAWhitelistedProp: 40px;\n" +
			"font-size: 40px;\n" +
			"}";

		try {
			validateAndSanitizeCss(styleContent);
			fail("Should not allow props that are not white-listed ");
		} catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
		}
	}

	@Test
	public void fail_on_blacklisted_value() {
		String styleContent = ".myClass table td {\n" +
			"font-size: \"expression(alert('XSS'))\";\n" +
			"}";


		try {
			validateAndSanitizeCss(styleContent);
			fail("Should not allow blacklisted words");
		} catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
		}
	}

	@Test
	public void allow_space_after_property_name() {
		String styleContent = ".myClass table td {\n" +
			"font-size   :   40px           ;\n" +
			"}";

		String actual = validateAndSanitizeCss(styleContent);
		assertThat(actual, is(styleContent));
	}

	@Test
	public void should_allow_empty_css() {
		String styleContent = "";

		String result = validateAndSanitizeCss(styleContent);
		assertThat(result, is(styleContent));
	}

	@Test
	public void should_allow_empty_property_and_value_css() {
		String styleContent = ".myClass table td {\n" +
			"}";

		String result = validateAndSanitizeCss(styleContent);
		assertThat(result, is(styleContent));
	}

	@Test
	public void fail_if_value_does_not_end_with_semicolon(){
		String styleContent = ".myClass table td {" +
			"font-size:40px" +
			"}";

		try {
			validateAndSanitizeCss(styleContent);
			fail();
		} catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
			assertThat(exp.getValidationErrors().get(0), containsString("must end with ';'."));
		}
	}

	@Test
	public void should_pass_if_value_is_whitelisted_for_prop() {
		String styleContent = ".myClass table td {\n" +
			"display: inline;" +
			"}";

		String result = validateAndSanitizeCss(styleContent);
		assertThat(result, is(styleContent));
	}

	@Test
	public void should_fail_if_value_is_not_defined_in_whitelist_for_prop(){
		String styleContent = ".myClass table td {" +
			"display:none;" +
			"}";

		try {
			validateAndSanitizeCss(styleContent);
			fail();
		} catch (CSSValidationException exp) {
			assertThat(exp.getValidationErrors(), where(List::size, is(1)));
			assertThat(exp.getValidationErrors().get(0), containsString("Value 'none' is not allowed for property 'display'."));
		}
	}

	@Test
	public void epikrise_css_is_valid() {
		String result = validateAndSanitizeCss(epikriseCss);
		assertThat(result, is(result));
	}

	private static final String epikriseCss = "html, body, div, span, applet, object, iframe, \n" +
		" h1, h2, h3, h4, h5, h6, p, blockquote, pre, \n" +
		" a, abbr, acronym, address, big, cite, code, \n" +
		" del, dfn, em, img, ins, kbd, q, s, samp, \n" +
		" small, strike, strong, sub, sup, tt, var, \n" +
		" b, u, i, center, \n" +
		" dl, dt, dd, ol, ul, li, \n" +
		" fieldset, form, label, legend, \n" +
		" table, caption, tbody, tfoot, thead, tr, th, td, \n" +
		" article, aside, canvas, details, embed,  \n" +
		" figure, figcaption, footer, header, hgroup,  \n" +
		" menu, nav, output, ruby, section, summary, \n" +
		" time, mark, audio, video { \n" +
		" \tmargin: 0; \n" +
		" \tpadding: 0; \n" +
		" \tborder: 0; \n" +
		" \tfont-size: 100%; \n" +
		" \tfont: inherit; \n" +
		" \tvertical-align: baseline; \n" +
		" } \n" +
		"  HTML5 display-role reset for older browsers  \n" +
		" article, aside, details, figcaption, figure,  \n" +
		" footer, header, hgroup, menu, nav, section { \n" +
		" \tdisplay: block; \n" +
		" } \n" +
		" body { \n" +
		" \tline-height: 1; \n" +
		" } \n" +
		" ol, ul { \n" +
		" \tlist-style: none; \n" +
		" } \n" +
		" table { \n" +
		" \tborder-collapse: collapse; \n" +
		" \tborder-spacing: 0; \n" +
		" } \n" +
		"\n" +
		"body {\n" +
		"\tfont-size: 16px;\n" +
		"\tmargin: 2.5cm;\n" +
		"\tline-height: 120%;\n" +
		"}\n" +
		"b {\n" +
		"\tfont-weight: bold;\n" +
		"}\n" +
		"\n" +
		"h2 {\n" +
		"\tfont-size: 1.4em;\n" +
		"}\n" +
		"\n" +
		"pre {\n" +
		"\tfont-family: Times New Roman;\n" +
		"\twhite-space: pre-wrap;\n" +
		"\twhite-space: -moz-pre-wrap !important;\n" +
		"\tword-wrap: break-word;\n" +
		"}\n" +
		"\n" +
		"table {\n" +
		"\tfont-family: Times New Roman;\n" +
		"\tborder-collapse: collapse;\n" +
		"}\n" +
		"\n" +
		"td {\n" +
		"\tpadding: 2px 10px 2px 0;\n" +
		"}\n" +
		"\n" +
		"div#header {\n" +
		"\twidth: 100%;\n" +
		"}\n" +
		"\n" +
		"div#logo {\n" +
		"\twidth: 30%;\n" +
		"\tfloat: left;\n" +
		"}\n" +
		"\n" +
		"div#headertext {\n" +
		"\ttext-align: right;\n" +
		"\tfont-size: 14px;\n" +
		"\tpadding-top: 20px;\n" +
		"}\n" +
		"\n" +
		"div#body {\n" +
		"\tclear: both;\n" +
		"\tpadding-top: 40px;\n" +
		"}";

}
