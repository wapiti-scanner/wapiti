<?php
/**
 * Calendly Block.
 *
 * @since 8.2.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Calendly;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'calendly';
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
 * Calendly block registration/dependency declaration.
 *
 * @param array  $attr    Array containing the Calendly block attributes.
 * @param string $content String containing the Calendly block content.
 *
 * @return string
 */
function load_assets( $attr, $content ) {

	if ( is_admin() ) {
		return;
	}
	$url = Jetpack_Gutenberg::validate_block_embed_url(
		get_attribute( $attr, 'url' ),
		array( 'calendly.com' )
	);
	if ( empty( $url ) ) {
		return;
	}

	/*
	 * Enqueue necessary scripts and styles.
	 */
	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	$style                   = get_attribute( $attr, 'style' );
	$hide_event_type_details = get_attribute( $attr, 'hideEventTypeDetails' );
	$background_color        = get_attribute( $attr, 'backgroundColor' );
	$text_color              = get_attribute( $attr, 'textColor' );
	$primary_color           = get_attribute( $attr, 'primaryColor' );
	$classes                 = Blocks::classes( FEATURE_NAME, $attr, array( 'calendly-style-' . $style ) );
	$block_id                = wp_unique_id( 'calendly-block-' );
	$is_amp_request          = Blocks::is_amp_request();

	if ( ! wp_script_is( 'jetpack-calendly-external-js' ) && ! $is_amp_request ) {
		enqueue_calendly_js();
	}

	$base_url = $url;
	$url      = add_query_arg(
		array(
			'hide_event_type_details' => (int) $hide_event_type_details,
			'background_color'        => sanitize_hex_color_no_hash( $background_color ),
			'text_color'              => sanitize_hex_color_no_hash( $text_color ),
			'primary_color'           => sanitize_hex_color_no_hash( $primary_color ),
		),
		$url
	);

	if ( 'link' === $style ) {
		if ( ! wp_style_is( 'jetpack-calendly-external-css' ) ) {
			wp_enqueue_style( 'jetpack-calendly-external-css', 'https://assets.calendly.com/assets/external/widget.css', null, JETPACK__VERSION );
		}

		// Render deprecated version of Calendly block if needed. New markup block button class before rendering here.
		if ( false === strpos( $content, 'wp-block-jetpack-button' ) ) {
			$content = deprecated_render_button_v1( $attr, $block_id, $classes, $url );
		} else {
			$content = str_replace( 'calendly-widget-id', esc_attr( $block_id ), $content );
			$content = str_replace( $base_url, $url, $content );
		}

		if ( ! $is_amp_request ) {
			wp_add_inline_script(
				'jetpack-calendly-external-js',
				sprintf( "calendly_attach_link_events( '%s' )", esc_js( $block_id ) )
			);
		}
	} elseif ( $is_amp_request ) { // Inline style.
		$content = sprintf(
			'<div class="%1$s" id="%2$s"><a href="%3$s" role="button" target="_blank">%4$s</a></div>',
			esc_attr( Blocks::classes( FEATURE_NAME, $attr ) ),
			esc_attr( $block_id ),
			esc_js( $url ),
			wp_kses_post( get_attribute( $attr, 'submitButtonText' ) )
		);
	} else {
		$content = sprintf(
			'<div class="%1$s" id="%2$s"></div>',
			esc_attr( $classes ),
			esc_attr( $block_id )
		);
		$script  = <<<JS_END
jetpackInitCalendly( '%s', '%s' );
JS_END;
		wp_add_inline_script( 'jetpack-calendly-external-js', sprintf( $script, esc_url( $url ), esc_js( $block_id ) ) );
	}

	return $content;
}

/**
 * Get filtered attributes.
 *
 * @param array  $attributes     Array containing the Calendly block attributes.
 * @param string $attribute_name String containing the attribute name to get.
 *
 * @return string
 */
function get_attribute( $attributes, $attribute_name ) {
	if ( isset( $attributes[ $attribute_name ] ) ) {
		return $attributes[ $attribute_name ];
	}

	$default_attributes = array(
		'style'                => 'inline',
		'submitButtonText'     => esc_html__( 'Schedule time with me', 'jetpack' ),
		'backgroundColor'      => 'ffffff',
		'textColor'            => '4D5055',
		'primaryColor'         => '00A2FF',
		'hideEventTypeDetails' => false,
	);

	if ( isset( $default_attributes[ $attribute_name ] ) ) {
		return $default_attributes[ $attribute_name ];
	}
}

/**
 * Enqueues the Calendly JS library and inline function to attach event
 * handlers to the button.
 *
 * @return void
 */
function enqueue_calendly_js() {
	wp_enqueue_script(
		'jetpack-calendly-external-js',
		'https://assets.calendly.com/assets/external/widget.js',
		null,
		JETPACK__VERSION,
		false
	);

	wp_add_inline_script(
		'jetpack-calendly-external-js',
		"function jetpackInitCalendly( url, elementId ) {
			function initCalendlyWidget() {
				if ( ! document.getElementById( elementId ) ) {
					return;
				}
				Calendly.initInlineWidget({
					url: url,
					parentElement: document.getElementById( elementId ),
					inlineStyles: false,
				});
			};
			// For P2s only: wait until after o2 has
			// replaced main#content to initialize widget.
			if ( window.jQuery && window.o2 ) {
				jQuery( 'body' ).on( 'ready_o2', function() { initCalendlyWidget() } );
			// Else initialize widget without waiting.
			} else {
				document.addEventListener('DOMContentLoaded', function() {
					initCalendlyWidget();
				});
			}
		};

		function calendly_attach_link_events( elementId ) {
			var widget = document.getElementById( elementId );
			if ( widget ) {
				widget.addEventListener( 'click', function( event ) {
					event.preventDefault();
					Calendly.initPopupWidget( { url: event.target.href } );
				} );
				widget.addEventListener( 'keydown', function( event ) {
					// Enter and space keys.
					if ( event.keyCode === 13 || event.keyCode === 32 ) {
						event.preventDefault();
						event.target && event.target.click();
					}
				} );
			}
		}"
	);
}

/**
 * Renders a deprecated legacy version of the button HTML.
 *
 * @param array  $attributes Array containing the Calendly block attributes.
 * @param string $block_id  The value for the ID attribute of the link.
 * @param string $classes   The CSS classes for the wrapper div.
 * @param string $url       Calendly URL for the link HREF.
 *
 * @return string
 */
function deprecated_render_button_v1( $attributes, $block_id, $classes, $url ) {
	// This is the legacy version, so create the full link content.
	$submit_button_text             = get_attribute( $attributes, 'submitButtonText' );
	$submit_button_classes          = get_attribute( $attributes, 'submitButtonClasses' );
	$submit_button_text_color       = get_attribute( $attributes, 'customTextButtonColor' );
	$submit_button_background_color = get_attribute( $attributes, 'customBackgroundButtonColor' );

	/*
	 * If we have some additional styles from the editor
	 * (a custom text color, custom bg color, or both )
	 * Let's add that CSS inline.
	 */
	if ( ! empty( $submit_button_text_color ) || ! empty( $submit_button_background_color ) ) {
		$inline_styles = sprintf(
			'#%1$s{%2$s%3$s}',
			esc_attr( $block_id ),
			! empty( $submit_button_text_color )
				? 'color:#' . sanitize_hex_color_no_hash( $submit_button_text_color ) . ';'
				: '',
			! empty( $submit_button_background_color )
				? 'background-color:#' . sanitize_hex_color_no_hash( $submit_button_background_color ) . ';'
				: ''
		);
		wp_add_inline_style( 'jetpack-calendly-external-css', $inline_styles );
	}

	return sprintf(
		'<div class="wp-block-button %1$s"><a id="%2$s" class="%3$s" href="%4$s" role="button">%5$s</a></div>',
		esc_attr( $classes ),
		esc_attr( $block_id ),
		! empty( $submit_button_classes ) ? esc_attr( $submit_button_classes ) : 'wp-block-button__link',
		esc_js( $url ),
		wp_kses_post( $submit_button_text )
	);
}
