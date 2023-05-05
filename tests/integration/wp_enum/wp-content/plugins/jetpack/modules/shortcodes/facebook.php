<?php
/**
 * Facebook embeds
 *
 * @package automattic/jetpack
 */

define( 'JETPACK_FACEBOOK_EMBED_REGEX', '#^https?://(www.)?facebook\.com/([^/]+)/(posts|photos)/([^/]+)?#' );
define( 'JETPACK_FACEBOOK_ALTERNATE_EMBED_REGEX', '#^https?://(www.)?facebook\.com/permalink.php\?([^\s]+)#' );
define( 'JETPACK_FACEBOOK_PHOTO_EMBED_REGEX', '#^https?://(www.)?facebook\.com/photo.php\?([^\s]+)#' );
define( 'JETPACK_FACEBOOK_PHOTO_ALTERNATE_EMBED_REGEX', '#^https?://(www.)?facebook\.com/([^/]+)/photos/([^/]+)?#' );
define( 'JETPACK_FACEBOOK_VIDEO_EMBED_REGEX', '#^https?://(www.)?facebook\.com/(?:video.php|watch\/?)\?([^\s]+)#' );
define( 'JETPACK_FACEBOOK_VIDEO_ALTERNATE_EMBED_REGEX', '#^https?://(www.)?facebook\.com/([^/]+)/videos/([^/]+)?#' );

/*
 * Example URL: https://www.facebook.com/VenusWilliams/posts/10151647007373076
 */
wp_embed_register_handler( 'facebook', JETPACK_FACEBOOK_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/*
 * Example URL: https://www.facebook.com/permalink.php?id=222622504529111&story_fbid=559431180743788
 */
wp_embed_register_handler( 'facebook-alternate', JETPACK_FACEBOOK_ALTERNATE_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/*
 * Photos are handled on a different endpoint; e.g. https://www.facebook.com/photo.php?fbid=10151609960150073&set=a.398410140072.163165.106666030072&type=1
 */
wp_embed_register_handler( 'facebook-photo', JETPACK_FACEBOOK_PHOTO_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/*
 * Photos (from pages for example) can be at
 */
wp_embed_register_handler( 'facebook-alternate-photo', JETPACK_FACEBOOK_PHOTO_ALTERNATE_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/*
 * Videos
 *
 * Formats:
 * https://www.facebook.com/video.php?v=2836814009877992
 * https://www.facebook.com/watch/?v=2836814009877992
 */
wp_embed_register_handler( 'facebook-video', JETPACK_FACEBOOK_VIDEO_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/*
 * Videos  https://www.facebook.com/WhiteHouse/videos/10153398464269238/
 */
wp_embed_register_handler( 'facebook-alternate-video', JETPACK_FACEBOOK_VIDEO_ALTERNATE_EMBED_REGEX, 'jetpack_facebook_embed_handler' );

/**
 * Callback to modify output of embedded Facebook posts.
 *
 * @param array  $matches Regex partial matches against the URL passed.
 * @param array  $attr    Attributes received in embed response.
 * @param string $url     Requested URL to be embedded.
 * @return string Facebook embed markup.
 */
function jetpack_facebook_embed_handler( $matches, $attr, $url ) {
	if (
		false !== strpos( $url, 'video.php' )
		|| false !== strpos( $url, '/videos/' )
		|| false !== strpos( $url, '/watch' )
	) {
		$embed = sprintf( '<div class="fb-video" data-allowfullscreen="true" data-href="%s"></div>', esc_url( $url ) );
	} else {
		$width = 552; // As of 01/2017, the default width of Facebook embeds when no width attribute provided.

		global $content_width;
		if ( is_numeric( $content_width ) && $content_width > 0 ) {
			$width = min( $width, $content_width );
		}

		$embed = sprintf( '<div class="fb-post" data-href="%s" data-width="%s"></div>', esc_url( $url ), esc_attr( $width ) );
	}

	// Skip rendering scripts in an AMP context.
	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		return $embed;
	}

	// since Facebook is a faux embed, we need to load the JS SDK in the wpview embed iframe.
	if (
		defined( 'DOING_AJAX' )
		&& DOING_AJAX
		// No need to check for a nonce here, that's already handled by Core further up.
		&& ! empty( $_POST['action'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing
		&& 'parse-embed' === $_POST['action'] // phpcs:ignore WordPress.Security.NonceVerification.Missing
	) {
		ob_start();
		wp_scripts()->do_items( array( 'jetpack-facebook-embed' ) );
		$scripts = ob_get_clean();
		return $embed . $scripts;
	} else {
		wp_enqueue_script( 'jetpack-facebook-embed' );
		return $embed;
	}
}

/**
 * Shortcode handler.
 *
 * @param array $atts Shortcode attributes.
 */
function jetpack_facebook_shortcode_handler( $atts ) {
	global $wp_embed;

	if ( empty( $atts['url'] ) ) {
		return;
	}

	if ( ! preg_match( JETPACK_FACEBOOK_EMBED_REGEX, $atts['url'] )
	&& ! preg_match( JETPACK_FACEBOOK_PHOTO_EMBED_REGEX, $atts['url'] )
	&& ! preg_match( JETPACK_FACEBOOK_VIDEO_EMBED_REGEX, $atts['url'] )
	&& ! preg_match( JETPACK_FACEBOOK_VIDEO_ALTERNATE_EMBED_REGEX, $atts['url'] ) ) {
		return;
	}

	return $wp_embed->shortcode( $atts, $atts['url'] );
}
add_shortcode( 'facebook', 'jetpack_facebook_shortcode_handler' );
