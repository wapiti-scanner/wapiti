<?php
/**
 * Theme Tools: Responsive videos enhancements.
 *
 * @package automattic/jetpack
 */

/**
 * Load the Responsive videos plugin
 */
function jetpack_responsive_videos_init() {

	/* If the doesn't theme support 'jetpack-responsive-videos', don't continue */
	if ( ! current_theme_supports( 'jetpack-responsive-videos' ) ) {
		return;
	}

	/* If the theme does support 'jetpack-responsive-videos', wrap the videos */
	add_filter( 'wp_video_shortcode', 'jetpack_responsive_videos_embed_html' );
	add_filter( 'video_embed_html', 'jetpack_responsive_videos_embed_html' );

	/* Only wrap oEmbeds if video */
	add_filter( 'embed_oembed_html', 'jetpack_responsive_videos_maybe_wrap_oembed', 10, 2 );
	add_filter( 'embed_handler_html', 'jetpack_responsive_videos_maybe_wrap_oembed', 10, 2 );

	/* Wrap videos in Buddypress */
	add_filter( 'bp_embed_oembed_html', 'jetpack_responsive_videos_embed_html' );

	/* Wrap Slideshare shortcodes */
	add_filter( 'jetpack_slideshare_shortcode', 'jetpack_responsive_videos_embed_html' );

	// Remove the Jetpack Responsive video wrapper in embed blocks on sites that support core Responsive embeds.
	if ( current_theme_supports( 'responsive-embeds' ) ) {
		add_filter( 'render_block', 'jetpack_responsive_videos_remove_wrap_oembed', 10, 2 );
	}
}
add_action( 'after_setup_theme', 'jetpack_responsive_videos_init', 99 );

/**
 * Adds a wrapper to videos and enqueue script
 *
 * @param string $html The video embed HTML.
 * @return string
 */
function jetpack_responsive_videos_embed_html( $html ) {
	if ( empty( $html ) || ! is_string( $html ) ) {
		return $html;
	}

	// Short-circuit for AMP responses, since custom scripts are not allowed in AMP and videos are naturally responsive.
	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		return $html;
	}

	// The customizer video widget wraps videos with a class of wp-video
	// mejs as of 4.9 apparently resizes videos too which causes issues
	// skip the video if it is wrapped in wp-video.
	$video_widget_wrapper = 'class="wp-video"';

	$mejs_wrapped = strpos( $html, $video_widget_wrapper );

	// If this is a video widget wrapped by mejs, return the html.
	if ( false !== $mejs_wrapped ) {
		return $html;
	}

	if ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) {
		wp_enqueue_script( 'jetpack-responsive-videos-script', plugins_url( 'responsive-videos/responsive-videos.js', __FILE__ ), array( 'jquery' ), '1.3', true );
	} else {
		wp_enqueue_script( 'jetpack-responsive-videos-min-script', plugins_url( 'responsive-videos/responsive-videos.min.js', __FILE__ ), array( 'jquery' ), '1.3', true );
	}

	// Enqueue CSS to ensure compatibility with all themes
	wp_enqueue_style(
		'jetpack-responsive-videos-style',
		plugins_url( 'responsive-videos/responsive-videos.css', __FILE__ ),
		array(),
		JETPACK__VERSION
	);

	return '<div class="jetpack-video-wrapper">' . $html . '</div>';
}

/**
 * Check if oEmbed is a `$video_patterns` provider video before wrapping.
 *
 * @param mixed  $html The cached HTML result, stored in post meta.
 * @param string $url  he attempted embed URL.
 *
 * @return string
 */
function jetpack_responsive_videos_maybe_wrap_oembed( $html, $url = null ) {
	if ( empty( $html ) || ! is_string( $html ) || ! $url ) {
		return $html;
	}

	// Short-circuit for AMP responses, since custom scripts are not allowed in AMP and videos are naturally responsive.
	if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
		return $html;
	}

	$jetpack_video_wrapper = '<div class="jetpack-video-wrapper">';

	$already_wrapped = strpos( $html, $jetpack_video_wrapper );

	// If the oEmbed has already been wrapped, return the html.
	if ( false !== $already_wrapped ) {
		return $html;
	}

	/**
	 * The oEmbed video providers.
	 *
	 * An allowed list of oEmbed video provider Regex patterns to check against before wrapping the output.
	 *
	 * @module theme-tools
	 *
	 * @since 3.8.0
	 *
	 * @param array $video_patterns oEmbed video provider Regex patterns.
	 */
	$video_patterns = apply_filters(
		'jetpack_responsive_videos_oembed_videos',
		array(
			'https?://((m|www)\.)?youtube\.com/watch',
			'https?://((m|www)\.)?youtube\.com/playlist',
			'https?://youtu\.be/',
			'https?://(.+\.)?vimeo\.com/',
			'https?://(www\.)?dailymotion\.com/',
			'https?://dai.ly/',
			'https?://(www\.)?hulu\.com/watch/',
			'https?://wordpress.tv/',
			'https?://(www\.)?funnyordie\.com/videos/',
			'https?://vine.co/v/',
			'https?://(www\.)?collegehumor\.com/video/',
			'https?://(www\.|embed\.)?ted\.com/talks/',
		)
	);

	// Merge patterns to run in a single preg_match call.
	$video_patterns = '(' . implode( '|', $video_patterns ) . ')';

	$is_video = preg_match( $video_patterns, $url );

	// If the oEmbed is a video, wrap it in the responsive wrapper.
	if ( false === $already_wrapped && 1 === $is_video ) {
		return jetpack_responsive_videos_embed_html( $html );
	}

	return $html;
}

/**
 * Remove the Jetpack Responsive video wrapper in embed blocks.
 *
 * @since 7.0.0
 *
 * @param string $block_content The block content about to be appended.
 * @param array  $block         The full block, including name and attributes.
 *
 * @return string $block_content String of rendered HTML.
 */
function jetpack_responsive_videos_remove_wrap_oembed( $block_content, $block ) {
	if (
		isset( $block['blockName'] )
		&& (
			false !== strpos( $block['blockName'], 'core-embed' ) // pre-WP 5.6 embeds (multiple embed blocks starting with 'core-embed').
			|| 'core/embed' === $block['blockName'] // WP 5.6 embed block format (single embed block w/ block variations).
		)
	) {
		$block_content = preg_replace( '#<div class="jetpack-video-wrapper">(.*?)</div>#', '${1}', $block_content );
	}

	return $block_content;
}
