<?php
/**
 * Compatibility functions for YouTube URLs and WP.com helper functions.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Manager as Connection_Manager;

/**
 * Required for class.media-extractor.php to match expected function naming convention.
 *
 * @param $url Can be just the $url or the whole $atts array.
 * @return bool|mixed The Youtube video ID via jetpack_get_youtube_id
 */
function jetpack_shortcode_get_youtube_id( $url ) {
	return jetpack_get_youtube_id( $url );
}

/**
 * Extract video ID from a YouTube url.
 *
 * @param string $url YouTube URL.
 * @return bool|mixed The Youtube video ID
 */
function jetpack_get_youtube_id( $url ) {
	// Do we have an $atts array?  Get first att
	if ( is_array( $url ) ) {
		$url = reset( $url );
	}

	$url = youtube_sanitize_url( $url );
	$url = wp_parse_url( $url );
	$id  = false;

	if ( ! isset( $url['query'] ) ) {
		return false;
	}

	parse_str( $url['query'], $qargs );

	if ( ! isset( $qargs['v'] ) && ! isset( $qargs['list'] ) ) {
		return false;
	}

	if ( isset( $qargs['list'] ) ) {
		$id = preg_replace( '|[^_a-z0-9-]|i', '', $qargs['list'] );
	}

	if ( empty( $id ) ) {
		$id = preg_replace( '|[^_a-z0-9-]|i', '', $qargs['v'] );
	}

	return $id;
}

if ( ! function_exists( 'youtube_sanitize_url' ) ) :
	/**
	 * Normalizes a YouTube URL to include a v= parameter and a query string free of encoded ampersands.
	 *
	 * @param string $url YouTube URL.
	 * @return string The normalized URL
	 */
	function youtube_sanitize_url( $url ) {
		$url = trim( $url, ' "' );
		$url = trim( $url );
		$url = str_replace( array( 'youtu.be/', '/v/', '#!v=', '&amp;', '&#038;', 'playlist' ), array( 'youtu.be/?v=', '/?v=', '?v=', '&', '&', 'videoseries' ), $url );

		// Replace any extra question marks with ampersands - the result of a URL like "https://www.youtube.com/v/9FhMMmqzbD8?fs=1&hl=en_US" being passed in.
		$query_string_start = strpos( $url, '?' );

		if ( false !== $query_string_start ) {
			$url = substr( $url, 0, $query_string_start + 1 ) . str_replace( '?', '&', substr( $url, $query_string_start + 1 ) );
		}

		return $url;
	}
endif;

/**
 * Merge in three string helper functions from WPCOM to make working with strings easier.
 *
 * @see WPCOM/wp-content/mu-plugins/string-helpers.php
 */
if ( ! function_exists( 'wp_startswith' ) ) :
	/**
	 * Check whether a string starts with a specific substring.
	 *
	 * @param string $haystack String we are filtering.
	 * @param string $needle The substring we are looking for.
	 * @return bool
	 */
	function wp_startswith( $haystack, $needle ) {
		if ( ! $haystack || ! $needle || ! is_scalar( $haystack ) || ! is_scalar( $needle ) ) {
			return false;
		}

		$haystack = (string) $haystack;
		$needle   = (string) $needle;

		if ( function_exists( 'str_starts_with' ) ) { // remove when PHP 8.0 is the minimum supported.
			return str_starts_with( $haystack, $needle ); // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions
		}
		return 0 === strpos( $haystack, $needle );
	}
endif;

if ( ! function_exists( 'wp_endswith' ) ) :
	/**
	 * Check whether a string ends with a specific substring.
	 *
	 * @param string $haystack String we are filtering.
	 * @param string $needle The substring we are looking for.
	 * @return bool
	 */
	function wp_endswith( $haystack, $needle ) {
		if ( ! $haystack || ! $needle || ! is_scalar( $haystack ) || ! is_scalar( $needle ) ) {
			return false;
		}

		$haystack = (string) $haystack;
		$needle   = (string) $needle;

		if ( function_exists( 'str_ends_with' ) ) { // remove when PHP 8.0 is the minimum supported.
			return str_ends_with( $haystack, $needle ); // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions

		}
		return $needle === substr( $haystack, -strlen( $needle ) );
	}
endif;

if ( ! function_exists( 'wp_in' ) ) :
	/**
	 * Checks whether a string contains a specific substring.
	 *
	 * @param string $needle The substring we are looking for.
	 * @param string $haystack String we are filtering.
	 * @return bool
	 */
	function wp_in( $needle, $haystack ) {
		if ( ! $haystack || ! $needle || ! is_scalar( $haystack ) || ! is_scalar( $needle ) ) {
			return false;
		}

		$haystack = (string) $haystack;
		$needle   = (string) $needle;

		if ( function_exists( 'str_contains' ) ) { // remove when PHP 8.0 is the minimum supported.
			return str_contains( $haystack, $needle ); // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions
		}

		return false !== strpos( $haystack, $needle );
	}
endif;

/**
 * Deprecated connection function.
 *
 * @param string $text Deprecated.
 * @deprecated 7.5 Use Connection_Manager instead.
 */
function jetpack_sha1_base64( $text ) {
	$connection = new Connection_Manager();
	return $connection->sha1_base64( $text );
}
