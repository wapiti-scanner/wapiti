<?php
/**
 * WPORG_Additional_CSS_Manager file
 *
 * Responsible with replacing the Core Additional CSS section with an upgrade nudge on Atomic.
 *
 * @package Jetpack
 */

namespace Automattic\Jetpack\Dashboard_Customizations;

/**
 * Class Atomic_Additional_CSS_Manager
 *
 * @package Automattic\Jetpack\Dashboard_Customizations
 */
class Atomic_Additional_CSS_Manager {

	/**
	 * The site domain.
	 *
	 * @var string
	 */
	private $domain;

	/**
	 * Atomic_Additional_CSS_Manager constructor.
	 *
	 * @param string $domain the Site domain.
	 */
	public function __construct( $domain ) {
		$this->domain = $domain;
	}

	/**
	 * Replace the Additional CSS section from Customiz¡er with an upgrade nudge.
	 *
	 * @param \WP_Customize_Manager $wp_customize_manager Core customize manager.
	 */
	public function register_nudge( \WP_Customize_Manager $wp_customize_manager ) {
		$nudge_url  = $this->get_nudge_url();
		$nudge_text = __( 'Purchase a Business Plan to<br> activate CSS customization', 'jetpack' );

		if (
			( defined( 'ENABLE_PRO_PLAN' ) && ENABLE_PRO_PLAN ) ||
			! empty( $_GET['enable_pro_plan'] ) || // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only used to customize output.
			! empty( $_COOKIE['enable_pro_plan'] )
		) {
			$nudge_text = __( 'Purchase a Pro Plan to<br> activate CSS customization', 'jetpack' );
			$nudge_url  = preg_replace( '/premium$/', 'pro', $nudge_url );
		}

		$nudge = new CSS_Customizer_Nudge(
			$nudge_url,
			$nudge_text
		);

		$wp_customize_manager->remove_control( 'custom_css' );
		$wp_customize_manager->remove_section( 'custom_css' );

		$nudge->customize_register_nudge( $wp_customize_manager );
	}

	/**
	 * Get the Nudge URL.
	 *
	 * @return string
	 */
	private function get_nudge_url() {
		return '/checkout/' . $this->domain . '/business';
	}
}
