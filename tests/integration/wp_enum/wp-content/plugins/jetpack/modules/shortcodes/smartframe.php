<?php
/**
 * Smartframe.io embed
 *
 * Example URL: https://mikael-korpela.smartframe.io/p/mantymetsa_1630927773870/7673dc41a775fb845cc26acf24f1fe4?t=rql1c6dbpv2
 * Example embed code: <script src="https://embed.smartframe.io/6ae67829d1264ee0ea6071a788940eae.js" data-image-id="mantymetsa_1630927773870" data-width="100%" data-max-width="1412px"></script>
 *
 * @package automattic/jetpack
 */

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	add_action( 'init', 'jetpack_smartframe_enable_embeds' );
} else {
	jetpack_smartframe_enable_embeds();
}

/**
 * Register smartframe as oembed provider. Add filter to reverse iframes to shortcode. Register [smartframe] shortcode.
 *
 * @since 10.2.0
 */
function jetpack_smartframe_enable_embeds() {
	// Support their oEmbed Endpoint.
	wp_oembed_add_provider( '#https?://(.*?)\.smartframe\.(io|net)/.*#i', 'https://oembed.smartframe.io/', true );

	// Allow script to be filtered to short code (so direct copy+paste can be done).
	add_filter( 'pre_kses', 'jetpack_shortcodereverse_smartframe' );

	// Actually display the smartframe Embed.
	add_shortcode( 'smartframe', 'jetpack_smartframe_shortcode' );
}

/**
 * Compose shortcode based on smartframe iframes.
 *
 * @since 10.2.0
 *
 * @param string $content Post content.
 *
 * @return mixed
 */
function jetpack_shortcodereverse_smartframe( $content ) {
	if ( ! is_string( $content ) || false === stripos( $content, 'embed.smartframe' ) ) {
		return $content;
	}

	// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
	$regexp     = '!<script\ssrc="https://embed\.smartframe\.(?:io|net)/(\w+)\.js"\sdata-image-id="(.*?)"(?:\sdata-width="(?:\d+(?:%|px))"\s)?(?:data-max-width="(\d+(%|px)))?"></script>!i';
	$regexp_ent = str_replace( '&amp;#0*58;', '&amp;#0*58;|&#0*58;', htmlspecialchars( $regexp, ENT_NOQUOTES ) );

	foreach ( compact( 'regexp', 'regexp_ent' ) as $regexp ) {
		if ( ! preg_match_all( $regexp, $content, $matches, PREG_SET_ORDER ) ) {
			continue;
		}

		foreach ( $matches as $match ) {
			// We need at least a script ID and an image ID.
			if ( ! isset( $match[1], $match[2] ) ) {
				continue;
			}
			$shortcode = sprintf(
				'[smartframe script-id="%1$s" image-id="%2$s"%3$s]',
				esc_attr( $match[1] ),
				esc_attr( $match[2] ),
				! empty( $match[3] ) ? ' max-width="' . esc_attr( $match[3] ) . '"' : ''
			);
			$content   = str_replace( $match[0], $shortcode, $content );
		}
	}
	/** This action is documented in modules/widgets/social-media-icons.php */
	do_action( 'jetpack_bump_stats_extras', 'html_to_shortcode', 'smartframe' );

	return $content;
}

/**
 * Parse shortcode arguments and render its output.
 *
 * @since 10.2.0
 *
 * @param array $atts Shortcode parameters.
 *
 * @return string
 */
function jetpack_smartframe_shortcode( $atts ) {
	if ( ! empty( $atts['image-id'] ) ) {
		$image_id = $atts['image-id'];
	} else {
		return '<!-- Missing smartframe image-id -->';
	}
	if ( ! empty( $atts['script-id'] ) ) {
		$script_id = $atts['script-id'];
	} else {
		return '<!-- Missing smartframe script-id -->';
	}

	$params = array(
		// ignore width for now, smartframe embed code has it "100%". % isn't allowed in oembed, making it 100px.
		// 'width'  => isset( $atts['width'] ) ? (int) $atts['width'] : null,.
		'max-width' => isset( $atts['max-width'] ) ? (int) $atts['max-width'] : null,
	);

	$embed_url = sprintf(
		'https://imagecards.smartframe.io/%1$s/%2$s',
		esc_attr( $script_id ),
		esc_attr( $image_id )
	);

	// wrap the embed with wp-block-embed__wrapper, otherwise it would be aligned to the very left of the viewport.
	return sprintf(
		'<div class="wp-block-embed__wrapper">%1$s</div>',
		wp_oembed_get( $embed_url, array_filter( $params ) )
	);
}
