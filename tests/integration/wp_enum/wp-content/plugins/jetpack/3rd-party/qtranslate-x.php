<?php
/**
 * 3rd party integration for qTranslate.
 *
 * @package automattic/jetpack
 */

/**
 * Prevent qTranslate X from redirecting REST calls.
 *
 * @since 5.3
 *
 * @param string $url_lang Language URL to redirect to.
 * @param string $url_orig Original URL.
 * @param array  $url_info  Pieces of original URL.
 *
 * @return bool
 */
function jetpack_no_qtranslate_rest_url_redirect( $url_lang, $url_orig, $url_info ) {
	if ( false !== strpos( $url_info['wp-path'], 'wp-json/jetpack' ) ) {
		return false;
	}
	return $url_lang;
}
add_filter( 'qtranslate_language_detect_redirect', 'jetpack_no_qtranslate_rest_url_redirect', 10, 3 );
