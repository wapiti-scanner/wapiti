<?php
/**
 * CSS_Nudge_Customize_Control file.
 * CSS Nudge implementation for Atomic and WPCOM.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

/**
 * Class CSS_Nudge_Customize_Control
 *
 * @package Automattic\Jetpack\Dashboard_Customizations
 */
class CSS_Nudge_Customize_Control extends \WP_Customize_Control {

	/**
	 * The type of the nudge.
	 *
	 * @var string
	 */
	public $type = 'cssNudge';

	/**
	 * The Call to Action URL.
	 *
	 * @var string
	 */
	public $cta_url;

	/**
	 * The nudge text displayed.
	 *
	 * @var string
	 */
	public $nudge_copy;

	/**
	 * Render the nudge on the page.
	 */
	public function render_content() {
		$cta_url           = $this->cta_url;
		$nudge_copy        = $this->nudge_copy;
		$nudge_button_copy = __( 'Upgrade Now', 'jetpack' );

		echo '<div class="nudge-container">
				<p>
					' . wp_kses( $nudge_copy, array( 'br' => array() ) ) . '
				</p>
				<div class="button-container">
					<button type="button" class="button-primary navigate-to" data-navigate-to-page="' . esc_url( $cta_url ) . '">' . esc_html( $nudge_button_copy ) . '</button>
				</div>
			</div>';
	}
}
