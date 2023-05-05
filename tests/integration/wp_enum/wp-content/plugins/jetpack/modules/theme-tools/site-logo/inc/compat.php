<?php
/**
 * Functions for maintaining backwards compatibility with unprefixed template tags from the original Site Logo plugin.
 * These should never be used in themes; instead, use the template tags in functions.php.
 * See: https://github.com/Automattic/jetpack/pull/956
 *
 * @package automattic/jetpack
 */

if ( ! function_exists( 'the_site_logo' ) ) :
	/**
	 * Unprefixed, backwards-compatible function for outputting the site logo.
	 *
	 * @uses jetpack_the_site_logo()
	 */
	function the_site_logo() {
		jetpack_the_site_logo();
	}
endif;

if ( ! function_exists( 'has_site_logo' ) ) :
	/**
	 * Unprefixed, backwards-compatible function for determining if a site logo has been set.
	 *
	 * @uses   jetpack_has_site_logo()
	 * @return bool True if a site logo is set, false otherwise.
	 */
	function has_site_logo() {
		return jetpack_has_site_logo();
	}
endif;

if ( ! function_exists( 'get_site_logo' ) ) :
	/**
	 * Unprefixed, backwards-compatible function for getting either the site logo's image URL or its ID.
	 *
	 * @param  string $show Return the site logo URL or ID.
	 * @uses   jetpack_get_site_logo()
	 * @return string Site logo ID or URL (the default).
	 */
	function get_site_logo( $show = 'url' ) {
		return jetpack_get_site_logo( $show );
	}
endif;
