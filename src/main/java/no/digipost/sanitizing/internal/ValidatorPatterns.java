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

import java.util.function.Predicate;
import java.util.regex.Pattern;

final class ValidatorPatterns {

	// The 16 colors defined by the HTML Spec (also used by the CSS Spec)
	static final Pattern COLOR_NAME = Pattern.compile("(?:aqua|black|blue|fuchsia|gray|grey|green|lime|maroon|navy|olive|purple|red|silver|teal|white|yellow)");
	// HTML/CSS Spec allows 3 or 6 digit hex to specify color
	static final Pattern COLOR_CODE = Pattern.compile("(?:#(?:[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?))");

    static final Pattern NUMBER_OR_PERCENT = Pattern.compile("[0-9]+%?");
	static final Pattern DIMENSION = Pattern.compile("^[0-9]+(%|px|em|rem)?$");
	static final Pattern PARAGRAPH = Pattern.compile("(?:[\\p{L}\\p{N},'.\\s\\-_()]|&[0-9]{2};)*");
	static final Pattern HTML_ID = Pattern.compile("[a-zA-Z0-9:\\-_.]+");

	// force non-empty with a '+' at the end instead of '*'
	static final Pattern HTML_TITLE = Pattern.compile("[\\p{L}\\p{N}\\s\\-_',:\\[\\]!./\\\\()&]*");
	static final Pattern HTML_CLASS = Pattern.compile("[a-zA-Z0-9\\s,\\-_]+");

	static final Pattern ONSITE_URL = Pattern.compile("(?:[\\p{L}\\p{N}\\\\.#@$%+&;\\-_~,?=/!]+|#(\\w)+)");
	static final Pattern OFFSITE_URL = Pattern.compile("\\s*(?:(?:ht|f)tps?://|mailto:)[\\p{L}\\p{N}][\\p{L}\\p{N}\\p{Zs}.#@$%+&;:\\-_~,?=/!()]*+\\s*");

	static final Pattern NUMBER = Pattern.compile("[+-]?(?:(?:[0-9]+(?:\\.[0-9]*)?)|\\.[0-9]+)");

	static final Pattern NAME = Pattern.compile("[a-zA-Z0-9\\-_$]+");

	static final Pattern ALIGN = Pattern.compile("(?i)center|left|right|justify|char");

    static final Pattern FLEX_BASIS = Pattern.compile("^(?:0|auto|content|\\d*\\.?\\d+(?:%|px|em|rem|))$");

	static final Pattern VALIGN = Pattern.compile("(?i)baseline|bottom|middle|top");

	static final Pattern TARGET_BLANK = Pattern.compile("_blank");

	static final Pattern CSS_TYPE = Pattern.compile("text/css");

	static final Predicate<String> COLOR_NAME_OR_COLOR_CODE = matchesEither(COLOR_NAME, COLOR_CODE);

	static final Predicate<String> ONSITE_OR_OFFSITE_URL = matchesEither(ONSITE_URL, OFFSITE_URL);

	static final Pattern IMAGE_DATA_URL = Pattern.compile("data:image/(gif|jpg|jpeg|png);base64.+");

	static final Pattern ONE_CHAR = Pattern.compile(".?", Pattern.DOTALL);

	static final Pattern TYPE_AND_CHARSET = Pattern.compile("text/html;[ ]*charset=([uU][tT][fF][\\-]?8|[iI][sS][oO]-8859-1)");

	static final Pattern META_VIEWPORT_VALUES = Pattern.compile("([, ;\\t]*(width|height|initial-scale|minimum-scale|maximum-scale|user-scalable|target-densityDpi)[ ]{0,3}=[ ]{0,3}(device-width|device-height|device-dpi|yes|no|[0-9.\\-]{1,4})){1,6}");



	private static Predicate<String> matchesEither(final Pattern a, final Pattern b) {
		return s -> a.matcher(s).matches() || b.matcher(s).matches();
	}
}
