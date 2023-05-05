<?php

namespace WPForms\Lite\Admin\Education\Builder;

use \WPForms\Admin\Education\EducationInterface;

/**
 * Builder/DidYouKnow Education feature.
 *
 * @since 1.6.6
 */
class DidYouKnow implements EducationInterface {

	/**
	 * Indicate if current Education feature is allowed to load.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'builder' );
	}

	/**
	 * Init.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		// Define hooks.
		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.6.6
	 */
	public function hooks() {

		add_action( 'wpforms_builder_settings_notifications_after', [ $this, 'notifications' ] );
		add_action( 'wpforms_builder_settings_confirmations_after', [ $this, 'confirmations' ] );
	}

	/**
	 * Display on the Notifications panel.
	 *
	 * @since 1.6.6
	 */
	public function notifications() {

		$this->display(
			'notifications',
			[ 'desc' => esc_html__( 'You can have multiple notifications with conditional logic.', 'wpforms-lite' ) ]
		);
	}

	/**
	 * Display on the Confirmations panel.
	 *
	 * @since 1.6.6
	 */
	public function confirmations() {

		$this->display(
			'confirmations',
			[ 'desc' => esc_html__( 'You can have multiple confirmations with conditional logic.', 'wpforms-lite' ) ]
		);
	}

	/**
	 * Display message.
	 *
	 * @since 1.6.6
	 *
	 * @param string $section  Form builder section/area (slug).
	 * @param array  $settings Notice settings array.
	 */
	private function display( $section, $settings ) {

		$dismissed = get_user_meta( get_current_user_id(), 'wpforms_dismissed', true );

		// Check if not dismissed.
		if ( ! empty( $dismissed[ 'edu-builder-did-you-know-' . $section ] ) ) {
			return;
		}

		echo wpforms_render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			'education/builder/did-you-know',
			[
				'desc'    => $settings['desc'],
				'more'    => ! empty( $settings['more'] ) ? $settings['more'] : '',
				'link'    => wpforms_admin_upgrade_link( 'Form Builder DYK', ucfirst( $section ) ),
				'section' => $section,

			],
			true
		);
	}
}
