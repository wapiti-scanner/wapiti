<?php
/**
 * Button Block.
 *
 * @since 8.5.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Button;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'button';
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
			'render_callback' => __NAMESPACE__ . '\render_block',
			'uses_context'    => array( 'jetpack/parentBlockWidth' ),
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Button block render callback.
 *
 * @param array  $attributes Array containing the Button block attributes.
 * @param string $content    The Button block content.
 *
 * @return string
 */
function render_block( $attributes, $content ) {
	$save_in_post_content = get_attribute( $attributes, 'saveInPostContent' );

	// The Jetpack Button block depends on the core button block styles.
	// The following ensures that those styles are enqueued when rendering this block.
	enqueue_existing_button_style_dependency( 'core/button' );
	enqueue_existing_button_style_dependency( 'core/buttons' );

	Jetpack_Gutenberg::load_styles_as_required( FEATURE_NAME );

	if ( $save_in_post_content || ! class_exists( 'DOMDocument' ) ) {
		return $content;
	}

	$element   = get_attribute( $attributes, 'element' );
	$text      = get_attribute( $attributes, 'text' );
	$unique_id = get_attribute( $attributes, 'uniqueId' );
	$url       = get_attribute( $attributes, 'url' );
	$classes   = Blocks::classes( FEATURE_NAME, $attributes, array( 'wp-block-button' ) );

	$button_classes = get_button_classes( $attributes );
	$button_styles  = get_button_styles( $attributes );
	$wrapper_styles = get_button_wrapper_styles( $attributes );

	$wrapper_attributes = sprintf( ' class="%s" style="%s"', esc_attr( $classes ), esc_attr( $wrapper_styles ) );
	$button_attributes  = sprintf( ' class="%s" style="%s"', esc_attr( $button_classes ), esc_attr( $button_styles ) );

	if ( empty( $unique_id ) ) {
		$button_attributes .= ' data-id-attr="placeholder"';
	} else {
		$button_attributes .= sprintf( ' data-id-attr="%1$s" id="%1$s"', esc_attr( $unique_id ) );
	}

	if ( 'a' === $element ) {
		$button_attributes .= sprintf( ' href="%s" target="_blank" role="button" rel="noopener noreferrer"', esc_url( $url ) );
	} elseif ( 'button' === $element ) {
		$button_attributes .= ' type="submit"';
	} elseif ( 'input' === $element ) {
		$button_attributes .= sprintf( ' type="submit" value="%s"', wp_strip_all_tags( $text, true ) );
	}

	$button = 'input' === $element
		? '<' . $element . $button_attributes . ' />'
		: '<' . $element . $button_attributes . '>' . $text . '</' . $element . '>';

	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	return '<div' . $wrapper_attributes . '>' . $button . '</div>';
}

/**
 * Get the Button block classes.
 *
 * @param array $attributes Array containing the block attributes.
 *
 * @return string
 */
function get_button_classes( $attributes ) {
	$classes                     = array( 'wp-block-button__link' );
	$has_class_name              = array_key_exists( 'className', $attributes );
	$has_named_text_color        = array_key_exists( 'textColor', $attributes );
	$has_custom_text_color       = array_key_exists( 'customTextColor', $attributes );
	$has_named_background_color  = array_key_exists( 'backgroundColor', $attributes );
	$has_custom_background_color = array_key_exists( 'customBackgroundColor', $attributes );
	$has_named_gradient          = array_key_exists( 'gradient', $attributes );
	$has_custom_gradient         = array_key_exists( 'customGradient', $attributes );
	$has_border_radius           = array_key_exists( 'borderRadius', $attributes );
	$has_font_size               = array_key_exists( 'fontSize', $attributes );

	if ( $has_font_size ) {
		$classes[] = 'has-' . $attributes['fontSize'] . '-font-size';
		$classes[] = 'has-custom-font-size';
	}

	if ( $has_class_name ) {
		$classes[] = $attributes['className'];
	}

	if ( $has_named_text_color || $has_custom_text_color ) {
		$classes[] = 'has-text-color';
	}
	if ( $has_named_text_color ) {
		$classes[] = sprintf( 'has-%s-color', $attributes['textColor'] );
	}

	if (
		$has_named_background_color ||
		$has_custom_background_color ||
		$has_named_gradient ||
		$has_custom_gradient
	) {
		$classes[] = 'has-background';
	}
	if ( $has_named_background_color && ! $has_custom_gradient ) {
		$classes[] = sprintf( 'has-%s-background-color', $attributes['backgroundColor'] );
	}
	if ( $has_named_gradient ) {
		$classes[] = sprintf( 'has-%s-gradient-background', $attributes['gradient'] );
	}

	// phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
	if ( $has_border_radius && 0 == $attributes['borderRadius'] ) {
		$classes[] = 'no-border-radius';
	}

	return implode( ' ', $classes );
}

/**
 * Get the Button block styles.
 *
 * @param array $attributes Array containing the block attributes.
 *
 * @return string
 */
function get_button_styles( $attributes ) {
	$styles                      = array();
	$has_named_text_color        = array_key_exists( 'textColor', $attributes );
	$has_custom_text_color       = array_key_exists( 'customTextColor', $attributes );
	$has_named_background_color  = array_key_exists( 'backgroundColor', $attributes );
	$has_custom_background_color = array_key_exists( 'customBackgroundColor', $attributes );
	$has_named_gradient          = array_key_exists( 'gradient', $attributes );
	$has_custom_gradient         = array_key_exists( 'customGradient', $attributes );
	$has_border_radius           = array_key_exists( 'borderRadius', $attributes );
	$has_width                   = array_key_exists( 'width', $attributes );
	$has_font_family             = array_key_exists( 'fontFamily', $attributes );
	$has_typography_styles       = array_key_exists( 'style', $attributes ) && array_key_exists( 'typography', $attributes['style'] );
	$has_custom_font_size        = $has_typography_styles && array_key_exists( 'fontSize', $attributes['style']['typography'] );
	$has_custom_text_transform   = $has_typography_styles && array_key_exists( 'textTransform', $attributes['style']['typography'] );

	if ( $has_font_family ) {
		$styles[] = sprintf( 'font-family: %s;', $attributes['fontFamily'] );
	}

	if ( $has_custom_font_size ) {
		$styles[] = sprintf( 'font-size: %s;', $attributes['style']['typography']['fontSize'] );
	}

	if ( $has_custom_text_transform ) {
		$styles[] = sprintf( 'text-transform: %s;', $attributes['style']['typography']['textTransform'] );
	}

	if ( ! $has_named_text_color && $has_custom_text_color ) {
		$styles[] = sprintf( 'color: %s;', $attributes['customTextColor'] );
	}

	if ( ! $has_named_background_color && ! $has_named_gradient && $has_custom_gradient ) {
		$styles[] = sprintf( 'background: %s;', $attributes['customGradient'] );
	}

	if (
		$has_custom_background_color &&
		! $has_named_background_color &&
		! $has_named_gradient &&
		! $has_custom_gradient
	) {
		$styles[] = sprintf( 'background-color: %s;', $attributes['customBackgroundColor'] );
	}

	// phpcs:ignore Universal.Operators.StrictComparisons.LooseNotEqual
	if ( $has_border_radius && 0 != $attributes['borderRadius'] ) {
		$styles[] = sprintf( 'border-radius: %spx;', $attributes['borderRadius'] );
	}

	if ( $has_width ) {
		$styles[] = sprintf( 'width: %s;', $attributes['width'] );
		$styles[] = 'max-width: 100%';
	}

	return implode( ' ', $styles );
}

/**
 * Get the Button wrapper block styles.
 *
 * @param array $attributes Array containing the block attributes.
 *
 * @return string
 */
function get_button_wrapper_styles( $attributes ) {
	$styles    = array();
	$has_width = array_key_exists( 'width', $attributes );

	if ( $has_width ) {
		$styles[] = 'max-width: 100%';
	}

	return implode( ' ', $styles );
}

/**
 * Get filtered attributes.
 *
 * @param array  $attributes     Array containing the Button block attributes.
 * @param string $attribute_name String containing the attribute name to get.
 *
 * @return string
 */
function get_attribute( $attributes, $attribute_name ) {
	if ( isset( $attributes[ $attribute_name ] ) ) {
		return $attributes[ $attribute_name ];
	}

	$default_attributes = array(
		'url'               => '#',
		'element'           => 'a',
		'saveInPostContent' => false,
	);

	if ( isset( $default_attributes[ $attribute_name ] ) ) {
		return $default_attributes[ $attribute_name ];
	}
}

/**
 * Enqueue style for an existing block.
 *
 * The Jetpack Button block depends on styles from the core button block.
 * In case that block is not already within the post content, we can use
 * this function to ensure the block's style assets are enqueued.
 *
 * @param string $block_name Block type name including namespace.
 */
function enqueue_existing_button_style_dependency( $block_name ) {
	$existing_block = \WP_Block_Type_Registry::get_instance()->get_registered( $block_name );
	if ( isset( $existing_block ) && ! empty( $existing_block->style ) ) {
		wp_enqueue_style( $existing_block->style );
	}
}
