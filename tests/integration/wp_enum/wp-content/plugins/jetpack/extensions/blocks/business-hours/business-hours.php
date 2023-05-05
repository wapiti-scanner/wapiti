<?php
/**
 * Business Hours Block.
 *
 * @since 7.1.0
 *
 * @package automattic/jetpack
 */

namespace Automattic\Jetpack\Extensions\Business_Hours;

use Automattic\Jetpack\Blocks;
use Jetpack_Gutenberg;

const FEATURE_NAME = 'business-hours';
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
			'render_callback' => __NAMESPACE__ . '\render',
			'supports'        => array(
				'color'      => array(
					'gradients' => true,
				),
				'spacing'    => array(
					'margin'  => true,
					'padding' => true,
				),
				'typography' => array(
					'fontSize'   => true,
					'lineHeight' => true,
				),
				'align'      => array( 'wide', 'full' ),
			),
		)
	);
}
add_action( 'init', __NAMESPACE__ . '\register_block' );

/**
 * Get's default days / hours to render a business hour block with no data provided.
 *
 * @return array
 */
function get_default_days() {
	return array(
		array(
			'name'  => 'Sun',
			'hours' => array(),
		),
		array(
			'name'  => 'Mon',
			'hours' => array(
				array(
					'opening' => '09:00',
					'closing' => '17:00',
				),
			),
		),
		array(
			'name'  => 'Tue',
			'hours' => array(
				array(
					'opening' => '09:00',
					'closing' => '17:00',
				),
			),
		),
		array(
			'name'  => 'Wed',
			'hours' => array(
				array(
					'opening' => '09:00',
					'closing' => '17:00',
				),
			),
		),
		array(
			'name'  => 'Thu',
			'hours' => array(
				array(
					'opening' => '09:00',
					'closing' => '17:00',
				),
			),
		),
		array(
			'name'  => 'Fri',
			'hours' => array(
				array(
					'opening' => '09:00',
					'closing' => '17:00',
				),
			),
		),
		array(
			'name'  => 'Sat',
			'hours' => array(),
		),
	);
}

/**
 * Dynamic rendering of the block.
 *
 * @param array $attributes Array containing the business hours block attributes.
 *
 * @return string
 */
function render( $attributes ) {
	global $wp_locale;

	if ( empty( $attributes['days'] ) || ! is_array( $attributes['days'] ) ) {
		$attributes['days'] = get_default_days();
	}

	$wrapper_attributes = \WP_Block_Supports::get_instance()->apply_block_supports();

	$start_of_week = (int) get_option( 'start_of_week', 0 );
	$time_format   = get_option( 'time_format' );
	$content       = sprintf(
		'<dl class="jetpack-business-hours%s%s"%s>',
		! empty( $attributes['className'] ) ? ' ' . esc_attr( $attributes['className'] ) : '',
		! empty( $wrapper_attributes['class'] ) ? ' ' . esc_attr( $wrapper_attributes['class'] ) : '',
		! empty( $wrapper_attributes['style'] ) ? ' style="' . esc_attr( $wrapper_attributes['style'] ) . '"' : ''
	);

	$days = array( 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat' );

	if ( $start_of_week ) {
		$chunk1             = array_slice( $attributes['days'], 0, $start_of_week );
		$chunk2             = array_slice( $attributes['days'], $start_of_week );
		$attributes['days'] = array_merge( $chunk2, $chunk1 );
	}

	foreach ( $attributes['days'] as $day ) {
		$content   .= '<div class="jetpack-business-hours__item"><dt class="' . esc_attr( $day['name'] ) . '">' .
					ucfirst( $wp_locale->get_weekday( array_search( $day['name'], $days, true ) ) ) .
					'</dt>';
		$content   .= '<dd class="' . esc_attr( $day['name'] ) . '">';
		$days_hours = '';

		foreach ( $day['hours'] as $key => $hour ) {
			$opening = strtotime( $hour['opening'] );
			$closing = strtotime( $hour['closing'] );
			if ( ! $opening || ! $closing ) {
				continue;
			}
			$days_hours .= sprintf(
				'%1$s - %2$s',
				gmdate( $time_format, $opening ),
				gmdate( $time_format, $closing )
			);
			if ( $key + 1 < count( $day['hours'] ) ) {
				$days_hours .= ', ';
			}
		}

		if ( empty( $days_hours ) ) {
			$days_hours = esc_html__( 'Closed', 'jetpack' );
		}
		$content .= $days_hours;
		$content .= '</dd></div>';
	}

	$content .= '</dl>';

	Jetpack_Gutenberg::load_assets_as_required( FEATURE_NAME );

	/**
	 * Allows folks to filter the HTML content for the Business Hours block
	 *
	 * @since 7.1.0
	 *
	 * @param string $content The default HTML content set by `jetpack_business_hours_render`
	 * @param array $attributes Attributes generated in the block editor for the Business Hours block
	 */
	return apply_filters( 'jetpack_business_hours_content', $content, $attributes );
}
