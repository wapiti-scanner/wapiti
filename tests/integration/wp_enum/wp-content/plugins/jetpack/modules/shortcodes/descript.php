<?php
/**
 * Descript.com embed
 *
 * Example URL: https://share.descript.com/view/jUxUmel6GyN
 * Example embed code: <iframe src="https://share.descript.com/embed/jUxUmel6GyN" width="640" height="360" frameborder="0" allowfullscreen></iframe>
 *
 * @package automattic/jetpack
 */

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	add_action( 'init', 'jetpack_descript_enable_embeds' );
} else {
	jetpack_descript_enable_embeds();
}

/**
 * Register descript as oembed provider. Add filter to reverse iframes to shortcode. Register [descript] shortcode.
 *
 * @since 10.4
 */
function jetpack_descript_enable_embeds() {
	// Support their oEmbed Endpoint.
	wp_oembed_add_provider( '#https?://share.descript.com/(?:view|embed)/\w+#i', 'https://api.descript.com/v2/oembed', true );

	// Allow script to be filtered to short code (so direct copy+paste can be done).
	add_filter( 'pre_kses', 'jetpack_shortcodereverse_descript' );

	// Actually display the descript Embed.
	add_shortcode( 'descript', 'jetpack_descript_shortcode' );
}

/**
 * Compose shortcode based on Descript iframes.
 *
 * @since 10.4
 *
 * @param string $content Post content.
 *
 * @return mixed
 */
function jetpack_shortcodereverse_descript( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'share.descript.com' ) ) {
		return $content;
	}

	$regexp = '/<iframe (?:loading="lazy" )?src="https:\/\/share.descript.com\/embed\/(\w+)" width="(\d+)" height="(\d+)" frameborder="0" allowfullscreen(?:="")?><\/iframe>/i';

	if ( preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
		foreach ( $matches as $match ) {
			// We need at least a id.
			if ( isset( $match[1] ) ) {
				$shortcode = sprintf(
					'[descript id="%1$s" width="%2$s" height="%3$s"]',
					esc_attr( $match[1] ),
					esc_attr( $match[2] ),
					esc_attr( $match[3] )
				);
				$content   = str_replace( $match[0], $shortcode, $content );
			}
		}
	}

	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'html_to_shortcode', 'descript' );

	return $content;
}

/**
 * Parse shortcode arguments and render its output.
 *
 * @since 10.4
 *
 * @param array $atts Shortcode parameters.
 *
 * @return string
 */
function jetpack_descript_shortcode( $atts ) {
	if ( ! empty( $atts['id'] ) ) {
		$id = $atts['id'];
	} else {
		return '<!-- Missing descript id -->';
	}

	if ( ! empty( $atts['width'] ) ) {
		$width = $atts['width'];
	} else {
		$width = '640';
	}

	if ( ! empty( $atts['height'] ) ) {
		$height = $atts['height'];
	} else {
		$height = '480';
	}

	$params = array(
		'id'     => esc_attr( $id ),
		'width'  => (int) $width,
		'height' => (int) $height,
	);

	$embed_url = sprintf(
		'https://share.descript.com/view/%1$s',
		esc_attr( $id )
	);

	$embed_code = wp_oembed_get( $embed_url, array_filter( $params ) );

	// wrap the embed with wp-block-embed__wrapper, otherwise it would be aligned to the very left of the viewport.
	return sprintf(
		'<div class="wp-block-embed__wrapper">%1$s</div>',
		$embed_code
	);
}
