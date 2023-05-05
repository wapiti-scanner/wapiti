<?php
/**
 * Vine shortcode
 * The service is now archived, but existing embeds are still accessible.
 *
 * Examples:
 * Vine embed code:
 * <iframe class="vine-embed" src="https://vine.co/v/bjHh0zHdgZT" width="600" height="600" frameborder="0"></iframe>
 * <script async src="//platform.vine.co/static/scripts/embed.js" charset="utf-8"></script>
 *
 * URL example:
 * https://vine.co/v/bjHh0zHdgZT/
 *
 * Embed shortcode examples:
 * [embed]https://vine.co/v/bjHh0zHdgZT[/embed]
 * [embed width="300"]https://vine.co/v/bjHh0zHdgZT[/embed]
 * [embed type="postcard" width="300"]https://vine.co/v/bjHh0zHdgZT[/embed]
 *
 * @package automattic/jetpack
 */

/**
 * Handle Vine embeds.
 *
 * @param array  $matches Results after parsing the URL using the regex in wp_embed_register_handler().
 * @param array  $attr    Embed attributes.
 * @param string $url     The original URL that was matched by the regex.
 * @param array  $rawattr The original unmodified attributes.
 * @return string The embed HTML.
 */
function vine_embed_video( $matches, $attr, $url, $rawattr ) {
	$max_height = 300;
	$type       = 'simple';

	// Only allow 'postcard' or 'simple' types.
	if (
		isset( $rawattr['type'] )
		&& 'postcard' === $rawattr['type']
	) {
		$type = 'postcard';
	}

	$vine_size = Jetpack::get_content_width();

	// If the user enters a value for width or height, we ignore the Jetpack::get_content_width().
	if ( isset( $rawattr['width'] ) || isset( $rawattr['height'] ) ) {
		// 300 is the minimum size that Vine provides for embeds. Lower than that, the postcard embeds looks weird.
		$vine_size = max( $max_height, min( $attr['width'], $attr['height'] ) );
	}

	if ( empty( $vine_size ) ) {
		$vine_size = $max_height;
	}

	$url       = 'https://vine.co/v/' . $matches[1] . '/embed/' . $type;
	$vine_html = sprintf(
		'<span class="embed-vine" style="display: block;"><iframe class="vine-embed" src="%1$s" width="%2$d" height="%3$d" frameborder="0"></iframe></span>',
		esc_url( $url ),
		(int) $vine_size,
		(int) $vine_size
	);

	wp_enqueue_script(
		'vine-embed',
		'https://platform.vine.co/static/scripts/embed.js',
		array(),
		JETPACK__VERSION,
		true
	);

	return $vine_html;
}
wp_embed_register_handler( 'jetpack_vine', '#https?://vine.co/v/([a-z0-9]+).*#i', 'vine_embed_video' );

/**
 * Display the Vine shortcode.
 *
 * @param array $atts Shortcode attributes.
 */
function vine_shortcode( $atts ) {
	global $wp_embed;

	if ( empty( $atts['url'] ) ) {
		return '';
	}

	if ( ! preg_match( '#https?://vine.co/v/([a-z0-9]+).*#i', $atts['url'] ) ) {
		return '';
	}

	return $wp_embed->shortcode( $atts, $atts['url'] );
}
add_shortcode( 'vine', 'vine_shortcode' );
