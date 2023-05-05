<?php

namespace WPForms\Admin\Settings;

use WPForms\Helpers\Transient;

/**
 * Modern Markup setting element.
 *
 * @since 1.8.1
 */
class ModernMarkup {

	/**
	 * Settings array.
	 *
	 * @since 1.8.1
	 *
	 * @var array
	 */
	private $settings;

	/**
	 * Initialize class.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.8.1
	 */
	public function hooks() {

		add_action( 'wpforms_create_form', [ $this, 'clear_transient' ] );
		add_action( 'wpforms_save_form', [ $this, 'clear_transient' ] );
		add_action( 'wpforms_delete_form', [ $this, 'clear_transient' ] );
		add_action( 'wpforms_form_handler_update_status', [ $this, 'clear_transient' ] );

		// Only continue if we are actually on the settings page.
		if ( ! wpforms_is_admin_page( 'settings' ) ) {
			return;
		}

		add_filter( 'wpforms_settings_defaults', [ $this, 'register_field' ] );
	}

	/**
	 * Register setting field.
	 *
	 * @since 1.8.1
	 *
	 * @param array $settings Settings data.
	 *
	 * @return array
	 */
	public function register_field( $settings ) {

		/**
		 * Allows to show/hide the Modern Markup setting field on the Settings page.
		 *
		 * @since 1.8.1
		 *
		 * @param mixed $is_disabled Whether the setting must be hidden.
		 */
		$is_hidden = apply_filters(
			'wpforms_admin_settings_modern_markup_register_field_is_hidden',
			wpforms_setting( 'modern-markup-hide-setting' )
		);

		if ( ! empty( $is_hidden ) ) {
			return $settings;
		}

		$modern_markup = [
			'id'   => 'modern-markup',
			'name' => esc_html__( 'Use Modern Markup', 'wpforms-lite' ),
			'desc' => sprintf(
				wp_kses( /* translators: %s - WPForms.com form markup setting URL. */
					__( 'Check this option to use modern markup, which has increased accessibility and allows you to easily customize your forms in the block editor. <a href="%s" target="_blank" rel="noopener noreferrer">Read our form styling documentation</a> to learn more.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				wpforms_utm_link( 'https://wpforms.com/docs/styling-your-forms/', 'settings-license', 'Form Markup Documentation' )
			),
			'type' => 'checkbox',
		];

		$is_disabled_transient = Transient::get( 'modern_markup_setting_disabled' );

		// Transient doesn't set or expired.
		if ( $is_disabled_transient === false ) {
			$forms                 = wpforms()->get( 'form' )->get( '', [ 'post_status' => 'publish' ] );
			$is_disabled_transient = wpforms_has_field_type( 'credit-card', $forms, true ) ? '1' : '0';

			// Re-check all the forms for the CC field once per day.
			Transient::set( 'modern_markup_setting_disabled', $is_disabled_transient, DAY_IN_SECONDS );
		}

		/**
		 * Allows to enable/disable the Modern Markup setting field on the Settings page.
		 *
		 * @since 1.8.1
		 *
		 * @param mixed $is_disabled Whether the Modern Markup setting must be disabled.
		 */
		$is_disabled = (bool) apply_filters(
			'wpforms_admin_settings_modern_markup_register_field_is_disabled',
			! empty( $is_disabled_transient )
		);

		$current_value = wpforms_setting( 'modern-markup' );

		// In the case it is disabled because of the legacy CC field, add corresponding description.
		if ( $is_disabled && ! empty( $is_disabled_transient ) && empty( $current_value ) ) {
			$modern_markup['disabled']      = true;
			$modern_markup['disabled_desc'] = sprintf(
				wp_kses( /* translators: %s - WPForms Stripe addon URL. */
					__( '<strong>You cannot use modern markup because you’re using the deprecated Credit Card field.</strong> If you’d like to use modern markup, replace your credit card field with a payment gateway like <a href="%s" target="_blank" rel="noopener noreferrer">Stripe</a>.', 'wpforms-lite' ),
					[
						'a'      => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
						'strong' => [],
					]
				),
				'https://wpforms.com/docs/how-to-install-and-use-the-stripe-addon-with-wpforms'
			);
		}

		$modern_markup = [
			'modern-markup' => $modern_markup,
		];

		$settings['general'] = wpforms_list_insert_after( $settings['general'], 'disable-css', $modern_markup );

		return $settings;
	}

	/**
	 * Clear transient in the case when the form is created/saved/deleted.
	 * So, next time when the user will open the Settings page,
	 * the Modern Markup setting will check for the legacy Credit Card field in all the forms again.
	 *
	 * @since 1.8.1
	 */
	public function clear_transient() {

		Transient::delete( 'modern_markup_setting_disabled' );
	}
}
