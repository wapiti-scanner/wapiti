<?php
/**
 * Create legacy buttons markup.
 *
 * @package Automattic\Jetpack\Extensions\Premium_Content
 */

namespace Automattic\Jetpack\Extensions\Premium_Content;

/**
 * Creates a subscribe/login buttons markup for legacy blocks.
 *
 * @param array  $attributes Block attributes.
 * @param string $content    String containing the block content.
 * @param object $block      Legacy block.
 *
 * @return string Subscribe/login buttons markup.
 */
function create_legacy_buttons_markup( $attributes, $content, $block ) {
	$button_styles = array();
	if ( ! empty( $attributes['customBackgroundButtonColor'] ) ) {
		array_push(
			$button_styles,
			sprintf(
				'background-color: %s',
				isset( $attributes['customBackgroundButtonColor'] ) ? sanitize_hex_color( $attributes['customBackgroundButtonColor'] ) : 'transparent'
			)
		);
	}
	if ( ! empty( $attributes['customTextButtonColor'] ) ) {
		array_push(
			$button_styles,
			sprintf(
				'color: %s',
				isset( $attributes['customTextButtonColor'] ) ? sanitize_hex_color( $attributes['customTextButtonColor'] ) : 'inherit'
			)
		);
	}
	$button_styles = implode( ';', $button_styles );

	$login_button = sprintf(
		'<div class="wp-block-button"><a role="button" href="%1$s" class="%2$s" style="%3$s">%4$s</a></div>',
		subscription_service()->access_url(),
		empty( $attributes['buttonClasses'] ) ? 'wp-block-button__link' : esc_attr( $attributes['buttonClasses'] ),
		esc_attr( $button_styles ),
		empty( $attributes['loginButtonText'] ) ? __( 'Log In', 'jetpack' ) : $attributes['loginButtonText']
	);

	$subscribe_button = \Jetpack_Memberships::get_instance()->render_button(
		array(
			'planId'                      => empty( $block->context['premium-content/planId'] ) ? 0 : $block->context['premium-content/planId'],
			'submitButtonClasses'         => empty( $attributes['buttonClasses'] ) ? 'wp-block-button__link' : esc_attr( $attributes['buttonClasses'] ),
			'customTextButtonColor'       => empty( $attributes['customTextButtonColor'] ) ? '' : esc_attr( $attributes['customTextButtonColor'] ),
			'customBackgroundButtonColor' => empty( $attributes['customBackgroundButtonColor'] ) ? '' : esc_attr( $attributes['customBackgroundButtonColor'] ),
			'submitButtonText'            => empty( $attributes['subscribeButtonText'] ) ? __( 'Subscribe', 'jetpack' ) : esc_attr( $attributes['subscribeButtonText'] ),
		),
		$content,
		$block
	);

	return "<div class='wp-block-premium-content-logged-out-view__buttons'>{$subscribe_button}{$login_button}</div>";
}
