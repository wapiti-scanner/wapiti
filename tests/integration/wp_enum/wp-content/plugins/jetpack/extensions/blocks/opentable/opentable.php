<?php
/**
 * OpenTable Block.
 *
 * @since 8.2
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\OpenTable;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'opentable';
const BLOCK_NAME   = 'jetpack/' . FEATURE_NAME;

/**
 * Registers the block for use in Gutenberg
 * This is done via an action so that we can disable
 * registration if we need to.
 */
function register_block() {
	Blocks::jetpack_register_block(
		BLOCK_NAME,
		array(
			'render_callback' => __NAMESPACE__ . '\load_assets',
			'plan_check'      => true,
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * OpenTable block registration/dependency declaration.
 *
 * @param array $attributes    Array containing the OpenTable block attributes.
 *
 * @return string
 */
function load_assets( $attributes ) {

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	$classes    = array();
	$class_name = get_attribute( $attributes, 'className' );
	$style      = get_attribute( $attributes, 'style' );

	if ( 'wide' === $style && jetpack_is_mobile() ) {
		$attributes = array_merge( $attributes, array( 'style' => 'standard' ) );
		$classes[]  = 'is-style-mobile';
	}

	// Handles case of deprecated version using theme instead of block styles.
	if ( ! $class_name || strpos( $class_name, 'is-style-' ) === false ) {
		$classes[] = sprintf( 'is-style-%s', $style );
	}

	if ( array_key_exists( 'rid', $attributes ) && is_array( $attributes['rid'] ) && count( $attributes['rid'] ) > 1 ) {
		$classes[] = 'is-multi';
	}
	if ( array_key_exists( 'negativeMargin', $attributes ) && $attributes['negativeMargin'] ) {
		$classes[] = 'has-no-margin';
	}
	$classes = Blocks::classes( FEATURE_NAME, $attributes, $classes );
	$content = '<div class="' . esc_attr( $classes ) . '">';

	$script_url = build_embed_url( $attributes );

	if ( Blocks::is_amp_request() ) {
		// Extract params from URL since it had jetpack_opentable_block_url filters applied.
		$url_query = \wp_parse_url( $script_url, PHP_URL_QUERY ) . '&overlay=false&disablega=false';

		$src = "https://www.opentable.com/widget/reservation/canvas?$url_query";

		$params = array();
		wp_parse_str( $url_query, $params );

		// Note an iframe is similarly constructed in the block edit function.
		$content .= sprintf(
			'<amp-iframe src="%s" layout="fill" sandbox="allow-scripts allow-forms allow-same-origin allow-popups">%s</amp-iframe>',
			esc_url( $src ),
			sprintf(
				'<a placeholder href="%s">%s</a>',
				esc_url(
					add_query_arg(
						array(
							'rid' => $params['rid'],
						),
						'https://www.opentable.com/restref/client/'
					)
				),
				esc_html__( 'Make a reservation', 'jetpack' )
			)
		);
	} else {
		// The OpenTable script uses multiple `rid` paramters,
		// so we can't use WordPress to output it, as WordPress attempts to validate it and removes them.
		// phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
		$content .= '<script src="' . esc_url( $script_url ) . '"></script>';
	}

	$content .= '</div>';

	return $content;
}

/**
 * Get the a block attribute
 *
 * @param array  $attributes Array of block attributes.
 * @param string $attribute_name The attribute to get.
 *
 * @return string The filtered attribute
 */
function get_attribute( $attributes, $attribute_name ) {
	if ( isset( $attributes[ $attribute_name ] ) ) {
		if ( in_array( $attribute_name, array( 'iframe', 'newtab' ), true ) ) {
			return $attributes[ $attribute_name ] ? 'true' : 'false';
		}
		return $attributes[ $attribute_name ];
	}

	$default_attributes = array(
		'style'  => 'standard',
		'iframe' => 'true',
		'domain' => 'com',
		'lang'   => 'en-US',
		'newtab' => 'false',
	);

	return isset( $default_attributes[ $attribute_name ] ) ? $default_attributes[ $attribute_name ] : null;
}

/**
 * Get the block type attribute
 *
 * @param array $attributes Array of block attributes.
 *
 * @return string The filtered attribute
 */
function get_type_attribute( $attributes ) {
	if ( ! empty( $attributes['rid'] ) && count( $attributes['rid'] ) > 1 ) {
		return 'multi';
	}

	if ( empty( $attributes['style'] ) || 'button' !== $attributes['style'] ) {
		return 'standard';
	}

	return 'button';
}

/**
 * Get the block theme attribute
 *
 * OpenTable has a confusing mix of themes and types for the widget. A type
 * can have a theme, but the button style can not have a theme. The other two
 * types (multi and standard) can have one of the three themes.
 *
 * We have combined these into a `style` attribute as really there are 4 styles
 * standard, wide, tall, and button. Multi can be determined by the number of
 * restaurant IDs we have.
 *
 * This function along with `jetpack_opentable_block_get_type_attribute`, translates
 * the style attribute to a type and theme.
 *
 * Type        Theme      Style
 * ==========|==========|==========
 * Multi     |          |
 * Standard  | Standard | Standard
 *           | Wide     | Wide
 *           | Tall     | Tall
 * Button    | Standard | Button
 *
 * @param array $attributes Array of block attributes.
 *
 * @return string The filtered attribute
 */
function get_theme_attribute( $attributes ) {
	$valid_themes = array( 'standard', 'wide', 'tall' );

	if ( empty( $attributes['style'] )
		|| ! in_array( $attributes['style'], $valid_themes, true )
		|| 'button' === $attributes['style'] ) {
		return 'standard';
	}

	return $attributes['style'];
}

/**
 * Build an embed URL from an array of block attributes.
 *
 * @param array $attributes Array of block attributess.
 *
 * @return string Embed URL
 */
function build_embed_url( $attributes ) {
	$url = add_query_arg(
		array(
			'type'   => get_type_attribute( $attributes ),
			'theme'  => get_theme_attribute( $attributes ),
			'iframe' => get_attribute( $attributes, 'iframe' ),
			'domain' => get_attribute( $attributes, 'domain' ),
			'lang'   => get_attribute( $attributes, 'lang' ),
			'newtab' => get_attribute( $attributes, 'newtab' ),
		),
		'//www.opentable.com/widget/reservation/loader'
	);

	if ( ! empty( $attributes['rid'] ) ) {
		foreach ( $attributes['rid'] as $rid ) {
			$url .= '&rid=' . $rid;
		}
	}

	/**
	 * Filter the OpenTable URL used to embed a widget.
	 *
	 * @since 8.2.0
	 *
	 * @param string $url        OpenTable embed URL.
	 * @param array  $attributes Array of block attributes.
	 */
	return apply_filters( 'jetpack_opentable_block_url', $url, $attributes );
}
