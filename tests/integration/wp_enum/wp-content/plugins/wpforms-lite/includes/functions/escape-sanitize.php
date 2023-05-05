<?php
/**
 * Helper functions to clean and sanitize data, escape it and prepare the output.
 *
 * @since 1.8.0
 */

use WPForms\Helpers\Templates;

/**
 * Decode special characters, both alpha- (<) and numeric-based (').
 * Sanitize recursively, preserve new lines.
 * Handle all the possible mixed variations of < and `&lt;` that can be processed into tags.
 *
 * @since 1.4.1
 * @since 1.6.0 Sanitize recursively, preserve new lines.
 *
 * @param string $string Raw string to decode.
 *
 * @return string
 */
function wpforms_decode_string( $string ) {

	if ( ! is_string( $string ) ) {
		return $string;
	}

	/*
	 * Sanitization should be done first, so tags are stripped and < is converted to &lt; etc.
	 * This iteration may do nothing when the string already comes with &lt; and &gt; only.
	 */
	$string = wpforms_sanitize_text_deeply( $string, true );

	// Now we need to convert the string without tags: &lt; back to < (same for quotes).
	$string = wp_kses_decode_entities( html_entity_decode( $string, ENT_QUOTES ) );

	// And now we need to sanitize AGAIN, to avoid unwanted tags that appeared after decoding.
	return wpforms_sanitize_text_deeply( $string, true );
}

/**
 * Sanitize key, primarily used for looking up options.
 *
 * @since 1.3.9
 *
 * @param string $key Key name.
 *
 * @return string
 */
function wpforms_sanitize_key( $key = '' ) {

	return preg_replace( '/[^a-zA-Z0-9_\-\.\:\/]/', '', $key );
}

/**
 * Sanitize hex color.
 *
 * @since 1.2.1
 *
 * @param string $color Color value.
 *
 * @return string
 */
function wpforms_sanitize_hex_color( $color ) {

	if ( empty( $color ) ) {
		return '';
	}

	// 3 or 6 hex digits, or the empty string.
	if ( preg_match( '|^#([A-Fa-f0-9]{3}){1,2}$|', $color ) ) {
		return $color;
	}

	return '';
}

/**
 * Sanitize error message, primarily used during form frontend output.
 *
 * @since 1.3.7
 * @since 1.7.6 Expand list of allowed HTML tags and attributes.
 *
 * @param string $error Error message.
 *
 * @return string
 */
function wpforms_sanitize_error( $error = '' ) {

	$allow = [
		'a'          => [
			'href'   => [],
			'title'  => [],
			'target' => [],
			'rel'    => [],
		],
		'br'         => [],
		'em'         => [],
		'strong'     => [],
		'del'        => [],
		'p'          => [
			'style' => [],
		],
		'blockquote' => [],
		'ul'         => [],
		'ol'         => [],
		'li'         => [],
		'span'       => [
			'style' => [],
		],
	];

	return wp_kses( $error, $allow );
}

/**
 * Sanitize a string, that can be a multiline.
 *
 * @uses wpforms_sanitize_text_deeply()
 *
 * @since 1.4.1
 *
 * @param string $string String to deeply sanitize.
 *
 * @return string Sanitized string, or empty string if not a string provided.
 */
function wpforms_sanitize_textarea_field( $string ) {

	return wpforms_sanitize_text_deeply( $string, true );
}

/**
 * Deeply sanitize the string, preserve newlines if needed.
 * Prevent maliciously prepared strings from containing HTML tags.
 *
 * @since 1.6.0
 *
 * @param string $string        String to deeply sanitize.
 * @param bool   $keep_newlines Whether to keep newlines. Default: false.
 *
 * @return string Sanitized string, or empty string if not a string provided.
 */
function wpforms_sanitize_text_deeply( $string, $keep_newlines = false ) {

	if ( is_object( $string ) || is_array( $string ) ) {
		return '';
	}

	$string        = (string) $string;
	$keep_newlines = (bool) $keep_newlines;

	$new_value = _sanitize_text_fields( $string, $keep_newlines );

	if ( strlen( $new_value ) !== strlen( $string ) ) {
		$new_value = wpforms_sanitize_text_deeply( $new_value, $keep_newlines );
	}

	return $new_value;
}

/**
 * Sanitize an HTML string with a set of allowed HTML tags.
 *
 * @since 1.7.0
 *
 * @param string $value String to sanitize.
 *
 * @return string Sanitized string.
 */
function wpforms_sanitize_richtext_field( $value ) {

	$count = 1;
	$value = convert_invalid_entities( $value );

	// Remove 'script' and 'style' tags recursively.
	while ( $count ) {
		$value = preg_replace( '@<(script|style)[^>]*?>.*?</\\1>@si', '', $value, - 1, $count );
	}

	// Make sure we have allowed tags only.
	$value = wp_kses( $value, wpforms_get_allowed_html_tags_for_richtext_field() );

	// Make sure that all tags are balanced.
	return force_balance_tags( $value );
}

/**
 * Escaping for Rich Text field values.
 *
 * @since 1.7.0
 *
 * @param string $value Text to escape.
 *
 * @return string Escaped text.
 */
function wpforms_esc_richtext_field( $value ) {

	return wpautop( wpforms_sanitize_richtext_field( $value ) );
}

/**
 * Retrieve allowed HTML tags for Rich Text field.
 *
 * @since 1.7.0
 *
 * @return array Array of allowed tags.
 */
function wpforms_get_allowed_html_tags_for_richtext_field() {

	$allowed_tags = array_fill_keys(
		[
			'img',
			'h1',
			'h2',
			'h3',
			'h4',
			'h5',
			'h6',
			'p',
			'a',
			'ul',
			'ol',
			'li',
			'dl',
			'dt',
			'dd',
			'hr',
			'br',
			'code',
			'pre',
			'strong',
			'b',
			'em',
			'i',
			'blockquote',
			'cite',
			'q',
			'del',
			'span',
			'small',
			'table',
			'thead',
			'tbody',
			'th',
			'tr',
			'td',
			'abbr',
			'address',
			'sub',
			'sup',
			'ins',
			'figure',
			'figcaption',
			'div',
		],
		array_fill_keys(
			[ 'align', 'class', 'id', 'style', 'src', 'rel', 'alt', 'href', 'target', 'width', 'height', 'title', 'cite', 'start', 'reversed', 'datetime' ],
			[]
		)
	);

	/**
	 * Allowed HTML tags for Rich Text field.
	 *
	 * @since 1.7.0
	 *
	 * @param array $allowed_tags Allowed HTML tags.
	 */
	$tags = (array) apply_filters( 'wpforms_get_allowed_html_tags_for_richtext_field', $allowed_tags );

	// Force unset iframes, script and style no matter when we get back
	// from apply_filters, as they are a huge security risk.
	unset( $tags['iframe'], $tags['script'], $tags['style'] );

	return $tags;
}

/**
 * Sanitize an array, that consists of values as strings.
 * After that - merge all array values into multiline string.
 *
 * @since 1.4.1
 *
 * @param array $array Data to sanitize.
 *
 * @return mixed If not an array is passed (or empty var) - return unmodified var. Otherwise - a merged array into multiline string.
 */
function wpforms_sanitize_array_combine( $array ) {

	if ( empty( $array ) || ! is_array( $array ) ) {
		return $array;
	}

	return implode( "\n", array_map( 'sanitize_text_field', $array ) );
}

/**
 * Format, sanitize, and return/echo HTML element ID, classes, attributes,
 * and data attributes.
 *
 * @since 1.3.7
 *
 * @param string $id    HTML id attribute value.
 * @param array  $class A list of classnames for the class attribute.
 * @param array  $datas Data attributes.
 * @param array  $atts  Any additional HTML attributes and their values.
 * @param bool   $echo  Whether to echo the output or just return it. Defaults to return.
 *
 * @return string|void
 */
function wpforms_html_attributes( $id = '', $class = [], $datas = [], $atts = [], $echo = false ) {

	$id    = trim( $id );
	$parts = [];

	if ( ! empty( $id ) ) {
		$id = sanitize_html_class( $id );

		if ( ! empty( $id ) ) {
			$parts[] = 'id="' . $id . '"';
		}
	}

	if ( ! empty( $class ) ) {
		$class = wpforms_sanitize_classes( $class, true );

		if ( ! empty( $class ) ) {
			$parts[] = 'class="' . $class . '"';
		}
	}

	if ( ! empty( $datas ) ) {
		foreach ( $datas as $data => $val ) {
			$parts[] = 'data-' . sanitize_html_class( $data ) . '="' . esc_attr( $val ) . '"';
		}
	}

	if ( ! empty( $atts ) ) {
		foreach ( $atts as $att => $val ) {
			if ( '0' === (string) $val || ! empty( $val ) ) {
				if ( $att[0] === '[' ) {
					// Handle special case for bound attributes in AMP.
					$escaped_att = '[' . sanitize_html_class( trim( $att, '[]' ) ) . ']';
				} else {
					$escaped_att = sanitize_html_class( $att );
				}
				$parts[] = $escaped_att . '="' . esc_attr( $val ) . '"';
			}
		}
	}

	$output = implode( ' ', $parts );

	if ( $echo ) {
		echo trim( $output ); // phpcs:ignore
	} else {
		return trim( $output );
	}
}

/**
 * Sanitize string of CSS classes.
 *
 * @since 1.2.1
 *
 * @param array|string $classes CSS classes.
 * @param bool         $convert True will convert strings to array and vice versa.
 *
 * @return string|array
 */
function wpforms_sanitize_classes( $classes, $convert = false ) {

	$array = is_array( $classes );
	$css   = [];

	if ( ! empty( $classes ) ) {
		if ( ! $array ) {
			$classes = explode( ' ', trim( $classes ) );
		}
		foreach ( array_unique( $classes ) as $class ) {
			if ( ! empty( $class ) ) {
				$css[] = sanitize_html_class( $class );
			}
		}
	}

	if ( $array ) {
		return $convert ? implode( ' ', $css ) : $css;
	}

	return $convert ? $css : implode( ' ', $css );
}

/**
 * Include a template - alias to \WPForms\Helpers\Template::get_html.
 * Use 'require' if $args are passed or 'load_template' if not.
 *
 * @since 1.5.6
 *
 * @param string $template_name Template name.
 * @param array  $args          Arguments.
 * @param bool   $extract       Extract arguments.
 *
 * @throws RuntimeException If extract() tries to modify the scope.
 *
 * @return string Compiled HTML.
 */
function wpforms_render( $template_name, $args = [], $extract = false ) {

	return Templates::get_html( $template_name, $args, $extract );
}

/**
 * Alias for default readonly function.
 *
 * @since 1.6.9
 *
 * @param mixed $readonly One of the values to compare.
 * @param mixed $current  The other value to compare if not just true.
 * @param bool  $echo     Whether to echo or just return the string.
 *
 * @return string HTML attribute or empty string.
 */
function wpforms_readonly( $readonly, $current = true, $echo = true ) {

	if ( function_exists( 'wp_readonly' ) ) {
		return wp_readonly( $readonly, $current, $echo );
	}

	return __checked_selected_helper( $readonly, $current, $echo, 'readonly' );
}

/**
 * Get the required label text, with a filter.
 *
 * @since 1.4.4
 *
 * @return string
 */
function wpforms_get_required_label() {

	return apply_filters( 'wpforms_required_label', esc_html__( 'This field is required.', 'wpforms-lite' ) );
}

/**
 * Get the required field label HTML, with a filter.
 *
 * @since 1.4.8
 *
 * @return string
 */
function wpforms_get_field_required_label() {

	$label_html = apply_filters_deprecated(
		'wpforms_field_required_label',
		[ ' <span class="wpforms-required-label">*</span>' ],
		'1.4.8 of the WPForms plugin',
		'wpforms_get_field_required_label'
	);

	return apply_filters( 'wpforms_get_field_required_label', $label_html );
}
