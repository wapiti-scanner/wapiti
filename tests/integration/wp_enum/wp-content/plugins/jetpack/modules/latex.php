<?php
/**
 * Module Name: Beautiful Math
 * Module Description: Use the LaTeX markup language to write mathematical equations and formulas
 * Sort Order: 12
 * First Introduced: 1.1
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Writing
 * Feature: Writing
 * Additional Search Queries: latex, math, equation, equations, formula, code
 *
 * @package automattic/jetpack
 */

/**
 * LaTeX support.
 *
 * Backward compatibility requires support for both "[latex][/latex]", and
 * "$latex $" shortcodes.
 *
 * $latex e^{\i \pi} + 1 = 0$  ->  [latex]e^{\i \pi} + 1 = 0[/latex]
 * $latex [a, b]$              ->  [latex][a, b][/latex]
 */

/**
 * Markup LaTeX content.
 *
 * @param string $content Post or comment contents to markup.
 */
function latex_markup( $content ) {
	$textarr = wp_html_split( $content );

	$regex = '%
		\$latex(?:=\s*|\s+)
		((?:
			[^$]+ # Not a dollar
		|
			(?<=(?<!\\\\)\\\\)\$ # Dollar preceded by exactly one slash
		)+)
		(?<!\\\\)\$ # Dollar preceded by zero slashes
	%ix';

	foreach ( $textarr as &$element ) {
		if ( '' === $element || '<' === $element[0] ) {
			continue;
		}

		if ( false === stripos( $element, '$latex' ) ) {
			continue;
		}

		$element = preg_replace_callback( $regex, 'latex_src', $element );
	}

	return implode( '', $textarr );
}

/**
 * Process LaTeX string to rendered image.
 *
 * @param array $matches Matched regex results.
 */
function latex_src( $matches ) {
	$latex = $matches[1];

	$bg = latex_get_default_color( 'bg' );
	$fg = latex_get_default_color( 'text', '000' );
	$s  = 0;

	$latex = latex_entity_decode( $latex );
	if ( preg_match( '/.+(&fg=[0-9a-f]{6}).*/i', $latex, $fg_matches ) ) {
		$fg    = substr( $fg_matches[1], 4 );
		$latex = str_replace( $fg_matches[1], '', $latex );
	}
	if ( preg_match( '/.+(&bg=[0-9a-f]{6}).*/i', $latex, $bg_matches ) ) {
		$bg    = substr( $bg_matches[1], 4 );
		$latex = str_replace( $bg_matches[1], '', $latex );
	}
	if ( preg_match( '/.+(&s=[0-9-]{1,2}).*/i', $latex, $s_matches ) ) {
		$s     = (int) substr( $s_matches[1], 3 );
		$latex = str_replace( $s_matches[1], '', $latex );
	}

	return latex_render( $latex, $fg, $bg, $s );
}

/**
 * Get the default color for an attribute.
 *
 * @param string $color Attribute to color (e.g. bg).
 * @param string $default_color Default fallback color to use.
 */
function latex_get_default_color( $color, $default_color = 'ffffff' ) {
	global $themecolors;
	return isset( $themecolors[ $color ] ) ? $themecolors[ $color ] : $default_color;
}

/**
 * Decode special characters in a LaTeX string.
 *
 * @param string $latex Character encoded content.
 */
function latex_entity_decode( $latex ) {
	return str_replace( array( '&lt;', '&gt;', '&quot;', '&#039;', '&#038;', '&amp;', "\n", "\r" ), array( '<', '>', '"', "'", '&', '&', ' ', ' ' ), $latex );
}

/**
 * Returns the URL for the server-side rendered image of LaTeX.
 *
 * @param string $latex LaTeX string.
 * @param string $fg Foreground color.
 * @param string $bg Background color.
 * @param int    $s Matches.
 *
 * @return string Image URL for the rendered LaTeX.
 */
function latex_render( $latex, $fg, $bg, $s = 0 ) {
	$url = add_query_arg(
		urlencode_deep(
			array(
				'latex' => $latex,
				'bg'    => $bg,
				'fg'    => $fg,
				's'     => $s,
				'c'     => '20201002', // cache buster. Added 2020-10-02 after server migration caused faulty rendering.
			)
		),
		( is_ssl() ? 'https://' : 'http://' ) . 's0.wp.com/latex.php'
	);

	$alt = str_replace( '\\', '&#92;', esc_attr( $latex ) );

	return sprintf(
		'<img src="%1$s" alt="%2$s" class="latex" />',
		esc_url( $url ),
		$alt
	);
}

/**
 * The shortcode way. The attributes are the same as the old ones - 'fg' and 'bg', instead of foreground
 * and background, and 's' is for the font size.
 *
 * Example: [latex s=4 bg=00f fg=ff0]\LaTeX[/latex]
 *
 * @param array  $atts Shortcode attributes.
 * @param string $content Content to format.
 */
function latex_shortcode( $atts, $content = '' ) {
	$attr = shortcode_atts(
		array(
			's'  => 0,
			'bg' => latex_get_default_color( 'bg' ),
			'fg' => latex_get_default_color( 'text', '000' ),
		),
		$atts,
		'latex'
	);

	return latex_render( latex_entity_decode( $content ), $attr['fg'], $attr['bg'], $attr['s'] );
}

/**
 * LaTeX needs to be untexturized.
 *
 * @param array $shortcodes Array of shortcodes not to texturize.
 */
function latex_no_texturize( $shortcodes ) {
	$shortcodes[] = 'latex';
	return $shortcodes;
}
add_filter( 'no_texturize_shortcodes', 'latex_no_texturize' );

add_filter( 'the_content', 'latex_markup', 9 ); // Before wptexturize.
add_filter( 'comment_text', 'latex_markup', 9 ); // Before wptexturize.
add_shortcode( 'latex', 'latex_shortcode' );
