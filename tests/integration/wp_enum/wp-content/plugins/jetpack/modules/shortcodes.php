<?php
/**
 * Module Name: Shortcode Embeds
 * Module Description: Shortcodes are WordPress-specific markup that let you add media from popular sites. This feature is no longer necessary as the editor now handles media embeds rather gracefully.
 * Sort Order: 3
 * First Introduced: 1.1
 * Major Changes In: 1.2
 * Requires Connection: No
 * Auto Activate: No
 * Module Tags: Photos and Videos, Social, Writing, Appearance
 * Feature: Writing
 * Additional Search Queries: shortcodes, shortcode, embeds, media, bandcamp, dailymotion, facebook, flickr, google calendars, google maps, polldaddy, recipe, recipes, scribd, slideshare, slideshow, slideshows, soundcloud, ted, twitter, vimeo, vine, youtube
 *
 * @package automattic/jetpack
 */

/**
 * Transforms the $atts array into a string that the old functions expected
 *
 * The old way was:
 * [shortcode a=1&b=2&c=3] or [shortcode=1]
 * This is parsed as array( a => '1&b=2&c=3' ) and array( 0 => '=1' ), which is useless
 *
 * @param array $params             Array of old shortcode parameters.
 * @param bool  $old_format_support true if [shortcode=foo] format is possible.
 *
 * @return string $params
 */
function shortcode_new_to_old_params( $params, $old_format_support = false ) {
	$str = '';

	if ( $old_format_support && isset( $params[0] ) ) {
		$str = ltrim( $params[0], '=' );
	} elseif ( is_array( $params ) ) {
		foreach ( array_keys( $params ) as $key ) {
			if ( ! is_numeric( $key ) ) {
				$str = $key . '=' . $params[ $key ];
			}
		}
	}

	return str_replace( array( '&amp;', '&#038;' ), '&', $str );
}

/**
 * Load all available Jetpack shortcode files.
 */
function jetpack_load_shortcodes() {
	$shortcode_includes = array();

	foreach ( Jetpack::glob_php( __DIR__ . '/shortcodes' ) as $file ) {
		$filename = substr( basename( $file ), 0, -4 );

		$shortcode_includes[ $filename ] = $file;
	}

	/**
	 * This filter allows other plugins to override which shortcodes Jetpack loads.
	 *
	 * Fires as part of the `plugins_loaded` WP hook, so modifying code needs to be in a plugin, not in a theme's functions.php.
	 *
	 * @module shortcodes
	 *
	 * @since 2.2.1
	 * @since 4.2.0 Added filename without extension as array key.
	 *
	 * @param array $shortcode_includes An array of which shortcodes to include.
	 */
	$shortcode_includes = apply_filters( 'jetpack_shortcodes_to_include', $shortcode_includes );

	foreach ( $shortcode_includes as $include ) {
		include_once $include;
	}
}

/**
 * Runs preg_replace so that replacements don't happen within open tags.
 * Parameters are the same as preg_replace, with an added optional search param for improved performance
 *
 * @param string $pattern     Pattern to search for.
 * @param string $replacement String to replace.
 * @param string $content     Post content.
 * @param string $search      String to search for.
 *
 * @return string $content    Replaced post content.
 */
function jetpack_preg_replace_outside_tags( $pattern, $replacement, $content, $search = null ) {
	if ( $search && false === strpos( $content, $search ) ) {
		return $content;
	}

	$textarr = wp_html_split( $content );
	unset( $content );
	foreach ( $textarr as &$element ) {
		if ( '' === $element || '<' === $element[0] ) {
			continue;
		}
		$element = preg_replace( $pattern, $replacement, $element );
	}

	return join( $textarr );
}

/**
 * Runs preg_replace_callback so that replacements don't happen within open tags.
 * Parameters are the same as preg_replace, with an added optional search param for improved performance.
 *
 * @param string $pattern  Pattern to search for.
 * @param string $callback Callback returning the replacement string.
 * @param string $content  Post content.
 * @param string $search   String to search for.
 *
 * @return string $content Replaced post content.
 */
function jetpack_preg_replace_callback_outside_tags( $pattern, $callback, $content, $search = null ) {
	if ( $search && false === strpos( $content, $search ) ) {
		return $content;
	}

	$textarr = wp_html_split( $content );
	unset( $content );
	foreach ( $textarr as &$element ) {
		if ( '' === $element || '<' === $element[0] ) {
			continue;
		}
		$element = preg_replace_callback( $pattern, $callback, $element );
	}

	return join( $textarr );
}

if ( ! function_exists( 'jetpack_shortcode_get_wpvideo_id' ) ) {
	/**
	 * Get VideoPress ID from wpvideo shortcode attributes.
	 *
	 * @param array $atts Shortcode attributes.
	 *
	 * @return string|int $id VideoPress ID.
	 */
	function jetpack_shortcode_get_wpvideo_id( $atts ) {
		if ( isset( $atts[0] ) ) {
			return $atts[0];
		} else {
			return 0;
		}
	}
}

if ( ! function_exists( 'jetpack_shortcode_get_videopress_id' ) ) {
	/**
	 * Get VideoPress ID from videopress shortcode attributes.
	 *
	 * @param array $atts Shortcode attributes.
	 * @return int  $id   VideoPress ID.
	 */
	function jetpack_shortcode_get_videopress_id( $atts ) {
		if ( isset( $atts[0] ) ) {
			return $atts[0];
		} else {
			return 0;
		}
	}
}

/**
 * Common element attributes parsing and sanitizing for src, width and height.
 *
 * @since 4.5.0
 *
 * @param array $attrs  With original values.
 *
 * @return array $attrs With sanitized values.
 */
function wpcom_shortcodereverse_parseattr( $attrs ) {
	$defaults = array(
		'src'    => false,
		'width'  => false,
		'height' => false,
	);

	$attrs = shortcode_atts( $defaults, $attrs );

	$attrs['src']    = wp_strip_all_tags( $attrs['src'] ); // For sanity.
	$attrs['width']  = ( is_numeric( $attrs['width'] ) ) ? abs( (int) $attrs['width'] ) : $defaults['width'];
	$attrs['height'] = ( is_numeric( $attrs['height'] ) ) ? abs( (int) $attrs['height'] ) : $defaults['height'];

	return $attrs;
}

/**
 * When an embed service goes away, we can use this handler
 * to output a link for history's sake.
 *
 * @param array  $matches Regex partial matches against the URL passed.
 * @param array  $attr    Attributes received in embed response.
 * @param string $url     Requested URL to be embedded.
 * @return string Link to output.
 */
function jetpack_deprecated_embed_handler( $matches, $attr, $url ) {
	return sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html( esc_url( $url ) ) );
}

jetpack_load_shortcodes();
