package io.modelcontextprotocol.util;

import java.net.URI;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;

/**
 * Implements URI Template handling according to RFC 6570. This class allows for the
 * expansion of URI templates with variables and also supports matching URIs against
 * templates to extract variables.
 * <p>
 * URI templates are strings with embedded expressions enclosed in curly braces, such as:
 * http://example.com/{username}/profile{?tab,section}
 */
public class UriTemplate {

	// Maximum allowed sizes to prevent DoS attacks
	private static final int MAX_TEMPLATE_LENGTH = 1000000; // 1MB

	private static final int MAX_VARIABLE_LENGTH = 1000000; // 1MB

	private static final int MAX_TEMPLATE_EXPRESSIONS = 10000;

	private static final int MAX_REGEX_LENGTH = 1000000; // 1MB

	// The original template string
	private final String template;

	// Parsed template parts (either strings or TemplatePart objects)
	private final List<Object> parts;

	/**
	 * Returns true if the given string contains any URI template expressions. A template
	 * expression is a sequence of characters enclosed in curly braces, like {foo} or
	 * {?bar}.
	 * @param str String to check for template expressions
	 * @return true if the string contains template expressions, false otherwise
	 */
	public static boolean isTemplate(String str) {
		// Look for any sequence of characters between curly braces
		// that isn't just whitespace
		return Pattern.compile("\\{[^}\\s]+\\}").matcher(str).find();
	}

	/**
	 * Validates that a string does not exceed the maximum allowed length.
	 * @param str String to validate
	 * @param max Maximum allowed length
	 * @param context Context description for error message
	 * @throws IllegalArgumentException if the string exceeds the maximum length
	 */
	private static void validateLength(String str, int max, String context) {
		if (str.length() > max) {
			throw new IllegalArgumentException(
					context + " exceeds maximum length of " + max + " characters (got " + str.length() + ")");
		}
	}

	/**
	 * Creates a new URI template instance.
	 * @param template The URI template string
	 * @throws IllegalArgumentException if the template is invalid or too long
	 */
	public UriTemplate(String template) {
		validateLength(template, MAX_TEMPLATE_LENGTH, "Template");
		this.template = template;
		this.parts = parse(template);
	}

	/**
	 * Returns the original template string.
	 */
	@Override
	public String toString() {
		return template;
	}

	/**
	 * Parses a URI template into a list of literal strings and template parts.
	 * @param template The URI template to parse
	 * @return List of parts (Strings for literals, TemplatePart objects for expressions)
	 * @throws IllegalArgumentException if the template is invalid
	 */
	private List<Object> parse(String template) {
		List<Object> parts = new ArrayList<>();
		StringBuilder currentText = new StringBuilder();
		int i = 0;
		int expressionCount = 0;

		while (i < template.length()) {
			if (template.charAt(i) == '{') {
				// End current text segment if any
				if (!currentText.isEmpty()) {
					parts.add(currentText.toString());
					currentText = new StringBuilder();
				}

				// Find closing brace
				int end = template.indexOf("}", i);
				if (end == -1)
					throw new IllegalArgumentException("Unclosed template expression");

				// Limit number of expressions to prevent DoS
				expressionCount++;
				if (expressionCount > MAX_TEMPLATE_EXPRESSIONS) {
					throw new IllegalArgumentException(
							"Template contains too many expressions (max " + MAX_TEMPLATE_EXPRESSIONS + ")");
				}

				// Parse the expression
				String expr = template.substring(i + 1, end);
				String operator = getOperator(expr);
				boolean exploded = expr.contains("*");
				List<String> names = getNames(expr);
				String name = names.get(0);

				// Validate variable name length
				for (String n : names) {
					validateLength(n, MAX_VARIABLE_LENGTH, "Variable name");
				}

				// Add the template part
				parts.add(new TemplatePart(name, operator, names, exploded));
				i = end + 1;
			}
			else {
				// Accumulate literal text
				currentText.append(template.charAt(i));
				i++;
			}
		}

		// Add any remaining literal text
		if (!currentText.isEmpty()) {
			parts.add(currentText.toString());
		}

		return parts;
	}

	/**
	 * Extracts the operator from a template expression. Operators are special characters
	 * at the beginning of the expression that change how the variables are expanded.
	 * @param expr The expression (contents inside curly braces)
	 * @return The operator ("+", "#", ".", "/", "?", "&", or "" if none)
	 */
	private String getOperator(String expr) {
		String[] operators = { "+", "#", ".", "/", "?", "&" };
		for (String op : operators) {
			if (expr.startsWith(op)) {
				return op;
			}
		}
		return "";
	}

	/**
	 * Extracts variable names from a template expression.
	 * @param expr The expression (contents inside curly braces)
	 * @return List of variable names
	 */
	private List<String> getNames(String expr) {
		String operator = getOperator(expr);
		List<String> names = new ArrayList<>();

		// Split by comma to get multiple variable names
		String[] nameParts = expr.substring(operator.length()).split(",");
		for (String name : nameParts) {
			String trimmed = name.replace("*", "").trim();
			if (!trimmed.isEmpty()) {
				names.add(trimmed);
			}
		}

		return names;
	}

	/**
	 * Encodes a value for inclusion in a URI according to the operator. Different
	 * operators have different encoding rules.
	 * @param value The value to encode
	 * @param operator The operator to determine encoding rules
	 * @return The encoded value
	 */
	private String encodeValue(String value, String operator) {
		validateLength(value, MAX_VARIABLE_LENGTH, "Variable value");
		try {
			if (operator.equals("+") || operator.equals("#")) {
				// For + and #, don't encode reserved characters
				return URI.create(value).toASCIIString();
			}
			// For other operators, fully URL encode the value
			// Replace + with %20 to ensure consistent handling of spaces
			return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
		}
		catch (Exception e) {
			throw new RuntimeException("Error encoding value: " + value, e);
		}
	}

	/**
	 * Expands a single template part using the provided variables.
	 * @param part The template part to expand
	 * @param variables Map of variable names to values
	 * @return The expanded string for this part
	 */
	private String expandPart(TemplatePart part, Map<String, Object> variables) {
		// Handle query parameters (? and & operators)
		if (part.operator.equals("?") || part.operator.equals("&")) {
			List<String> pairs = new ArrayList<>();

			for (String name : part.names) {
				Object value = variables.get(name);
				if (value == null)
					continue;

				String encoded;
				if (value instanceof List) {
					// Handle list values
					@SuppressWarnings("unchecked")
					List<String> listValue = (List<String>) value;
					encoded = listValue.stream()
						.map(v -> encodeValue(v, part.operator))
						.collect(Collectors.joining(","));
				}
				else {
					encoded = encodeValue(value.toString(), part.operator);
				}

				pairs.add(name + "=" + encoded);
			}

			if (pairs.isEmpty())
				return "";

			String separator = part.operator.equals("?") ? "?" : "&";
			return separator + String.join("&", pairs);
		}

		// Handle multiple variables in one expression
		if (part.names.size() > 1) {
			List<String> values = new ArrayList<>();
			for (String name : part.names) {
				Object value = variables.get(name);
				if (value != null) {
					if (value instanceof List) {
						@SuppressWarnings("unchecked")
						List<String> listValue = (List<String>) value;
						if (!listValue.isEmpty()) {
							values.add(listValue.get(0));
						}
					}
					else {
						values.add(value.toString());
					}
				}
			}

			if (values.isEmpty())
				return "";
			return String.join(",", values);
		}

		// Handle single variable
		Object value = variables.get(part.name);
		if (value == null)
			return "";

		List<String> values;
		if (value instanceof List) {
			@SuppressWarnings("unchecked")
			List<String> listValue = (List<String>) value;
			values = listValue;
		}
		else {
			values = List.of(value.toString());
		}

		List<String> encoded = values.stream().map(v -> encodeValue(v, part.operator)).collect(Collectors.toList());

		// Format according to operator
		return switch (part.operator) {
			case "#" -> "#" + String.join(",", encoded);
			case "." -> "." + String.join(".", encoded);
			case "/" -> "/" + String.join("/", encoded);
			default -> String.join(",", encoded);
		};
	}

	/**
	 * Expands the URI template by replacing variables with their values.
	 * @param variables Map of variable names to values
	 * @return The expanded URI
	 */
	public String expand(Map<String, Object> variables) {
		StringBuilder result = new StringBuilder();
		boolean hasQueryParam = false;

		for (Object part : parts) {
			if (part instanceof String) {
				// Literal part
				result.append(part);
				continue;
			}

			// Template part
			TemplatePart templatePart = (TemplatePart) part;
			String expanded = expandPart(templatePart, variables);
			if (expanded.isEmpty())
				continue;

			// Convert ? to & if we already have a query parameter
			if ((templatePart.operator.equals("?") || templatePart.operator.equals("&")) && hasQueryParam) {
				result.append(expanded.replace("?", "&"));
			}
			else {
				result.append(expanded);
			}

			// Track if we've added a query parameter
			if (templatePart.operator.equals("?") || templatePart.operator.equals("&")) {
				hasQueryParam = true;
			}
		}

		return result.toString();
	}

	/**
	 * Escapes special characters in a string for use in a regular expression.
	 * @param str The string to escape
	 * @return The escaped string
	 */
	private String escapeRegExp(String str) {
		return Pattern.quote(str);
	}

	/**
	 * Converts a template part to a regular expression pattern for matching.
	 * @param part The template part
	 * @return List of pattern information including the regex and variable name
	 */
	private List<PatternInfo> partToRegExp(TemplatePart part) {
		List<PatternInfo> patterns = new ArrayList<>();

		// Validate variable name length for matching
		for (String name : part.names) {
			validateLength(name, MAX_VARIABLE_LENGTH, "Variable name");
		}

		// Handle query parameters
		if (part.operator.equals("?") || part.operator.equals("&")) {
			for (int i = 0; i < part.names.size(); i++) {
				String name = part.names.get(i);
				String prefix = i == 0 ? "\\" + part.operator : "&";
				patterns.add(new PatternInfo(prefix + escapeRegExp(name) + "=([^&]+)", name));
			}
			return patterns;
		}

		String pattern;
		String name = part.name;

		// Create pattern based on operator
		pattern = switch (part.operator) {
			case "" -> part.exploded ? "([^/]+(?:,[^/]+)*)" : "([^/,]+)";
			case "+", "#" -> "(.+)";
			case "." -> "\\.([^/,]+)";
			case "/" -> "/" + (part.exploded ? "([^/]+(?:,[^/]+)*)" : "([^/,]+)");
			default -> "([^/]+)";
		};

		patterns.add(new PatternInfo(pattern, name));
		return patterns;
	}

	/**
	 * Matches a URI against this template and extracts variable values.
	 * @param uri The URI to match
	 * @return Map of variable names to extracted values, or null if the URI doesn't match
	 */
	public Map<String, Object> match(String uri) {
		validateLength(uri, MAX_TEMPLATE_LENGTH, "URI");
		StringBuilder patternBuilder = new StringBuilder("^");
		List<NameInfo> names = new ArrayList<>();

		// Build regex pattern from template parts
		for (Object part : parts) {
			if (part instanceof String) {
				patternBuilder.append(escapeRegExp((String) part));
			}
			else {
				TemplatePart templatePart = (TemplatePart) part;
				List<PatternInfo> patterns = partToRegExp(templatePart);
				for (PatternInfo patternInfo : patterns) {
					patternBuilder.append(patternInfo.pattern);
					names.add(new NameInfo(patternInfo.name, templatePart.exploded));
				}
			}
		}

		patternBuilder.append("$");
		String patternStr = patternBuilder.toString();
		validateLength(patternStr, MAX_REGEX_LENGTH, "Generated regex pattern");

		// Perform matching
		Pattern pattern = Pattern.compile(patternStr);
		Matcher matcher = pattern.matcher(uri);

		if (!matcher.matches())
			return null;

		// Extract values from match groups
		Map<String, Object> result = new HashMap<>();
		for (int i = 0; i < names.size(); i++) {
			NameInfo nameInfo = names.get(i);
			String value = matcher.group(i + 1);
			String cleanName = nameInfo.name.replace("*", "");

			// Handle exploded values (comma-separated lists)
			if (nameInfo.exploded && value.contains(",")) {
				result.put(cleanName, List.of(value.split(",")));
			}
			else {
				result.put(cleanName, value);
			}
		}

		return result;
	}

	/**
	 * Represents a template expression part with its operator and variables.
	 */
	private static class TemplatePart {

		final String name; // Primary variable name

		final String operator; // Operator character

		final List<String> names; // All variable names in this expression

		final boolean exploded; // Whether the variable is exploded with *

		TemplatePart(String name, String operator, List<String> names, boolean exploded) {
			this.name = name;
			this.operator = operator;
			this.names = names;
			this.exploded = exploded;
		}

	}

	/**
	 * Stores information about a regex pattern for a template part.
	 */
	private static class PatternInfo {

		final String pattern; // Regex pattern for matching

		final String name; // Variable name to extract

		PatternInfo(String pattern, String name) {
			this.pattern = pattern;
			this.name = name;
		}

	}

	/**
	 * Stores information about a variable name for matching.
	 */
	private static class NameInfo {

		final String name; // Variable name

		final boolean exploded; // Whether it's exploded with *

		NameInfo(String name, boolean exploded) {
			this.name = name;
			this.exploded = exploded;
		}

	}

}