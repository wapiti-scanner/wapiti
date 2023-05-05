<?php

namespace WPForms\Integrations\WPMailSMTP;

use WPMailSMTP\Options;
use WPForms\Integrations\IntegrationInterface;

/**
 * WP Mail SMTP hints inside form builder notifications.
 *
 * @since 1.4.8
 */
class Notifications implements IntegrationInterface {

	/**
	 * WP Mail SMTP options.
	 *
	 * @since 1.4.8
	 *
	 * @var Options
	 */
	public $options;

	/**
	 * Indicate if current integration is allowed to load.
	 *
	 * @since 1.4.8
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'builder' ) && function_exists( 'wp_mail_smtp' );
	}

	/**
	 * Load an integration.
	 *
	 * @since 1.4.8
	 */
	public function load() {

		$this->options = new Options();

		$this->hooks();
	}

	/**
	 * Integration filters.
	 *
	 * @since 1.4.8
	 */
	protected function hooks() {

		add_filter( 'wpforms_builder_notifications_from_name_after', [ $this, 'from_name_after' ] );
		add_filter( 'wpforms_builder_notifications_from_email_after', [ $this, 'from_email_after' ] );
		add_filter( 'wpforms_builder_notifications_sender_name_settings', [ $this, 'change_from_name_settings' ], 10, 3 );
		add_filter( 'wpforms_builder_notifications_sender_address_settings', [ $this, 'change_from_email_settings' ], 10, 3 );
		add_action( 'wpforms_form_settings_notifications_single_after', [ $this, 'add_hidden_from_name_field' ], 10, 2 );
		add_action( 'wpforms_form_settings_notifications_single_after', [ $this, 'add_hidden_from_email_field' ], 10, 2 );
	}

	/**
	 * Redefine From Name settings with data from WP Mail SMTP.
	 *
	 * @since 1.7.6
	 *
	 * @param array $args      Field settings.
	 * @param array $form_data Form data.
	 * @param int   $id        Notification ID.
	 *
	 * @return array
	 */
	public function change_from_name_settings( $args, $form_data, $id ) {

		if ( ! $this->options->get( 'mail', 'from_name_force' ) ) {
			return $args;
		}

		$args['value'] = $this->options->get( 'mail', 'from_name' );

		unset( $args['smarttags'] );

		return $args;
	}

	/**
	 * Redefine From Email settings with data from WP Mail SMTP.
	 *
	 * @since 1.7.6
	 *
	 * @param array $args      Field settings.
	 * @param array $form_data Form data.
	 * @param int   $id        Notification ID.
	 *
	 * @return array
	 */
	public function change_from_email_settings( $args, $form_data, $id ) {

		if ( ! $this->options->get( 'mail', 'from_email_force' ) ) {
			return $args;
		}

		$args['value'] = $this->options->get( 'mail', 'from_email' );

		unset( $args['smarttags'] );

		return $args;
	}

	/**
	 * Add hidden From Name field to overwrite value from WP Mail SMTP.
	 *
	 * @since 1.7.6
	 *
	 * @param array $settings Form settings.
	 * @param int   $id       Notification id.
	 */
	public function add_hidden_from_name_field( $settings, $id ) {

		if ( empty( $settings->form_data['settings']['notifications'][ $id ]['sender_name'] ) || ! $this->options->get( 'mail', 'from_name_force' ) ) {
			return;
		}

		wpforms_panel_field(
			'text',
			'notifications',
			'sender_name',
			$settings->form_data,
			'',
			[
				'parent'     => 'settings',
				'subsection' => $id,
				'readonly'   => true,
				'class'      => 'wpforms-hidden',
				'value'      => $settings->form_data['settings']['notifications'][ $id ]['sender_name'],
			]
		);
	}

	/**
	 * Add hidden From Email field to overwrite value from WP Mail SMTP.
	 *
	 * @since 1.7.6
	 *
	 * @param array $settings Form settings.
	 * @param int   $id       Notification id.
	 */
	public function add_hidden_from_email_field( $settings, $id ) {

		if ( empty( $settings->form_data['settings']['notifications'][ $id ]['sender_address'] ) || ! $this->options->get( 'mail', 'from_email_force' ) ) {
			return;
		}

		wpforms_panel_field(
			'text',
			'notifications',
			'sender_address',
			$settings->form_data,
			'',
			[
				'parent'     => 'settings',
				'subsection' => $id,
				'readonly'   => true,
				'class'      => 'wpforms-hidden',
				'value'      => $settings->form_data['settings']['notifications'][ $id ]['sender_address'],
			]
		);
	}

	/**
	 * Display hint if WP Mail SMTP is forcing from name.
	 *
	 * @since 1.4.8
	 *
	 * @param string $after Text displayed after setting.
	 *
	 * @return string
	 */
	public function from_name_after( $after ) {

		if ( ! $this->options->get( 'mail', 'from_name_force' ) ) {
			return $after;
		}

		return sprintf(
			wp_kses( /* translators: %s - URL WP Mail SMTP settings. */
				__( 'This setting is disabled because you have the "Force From Name" setting enabled in the <a href="%s" target="_blank">WP Mail SMTP</a> plugin.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
					],
				]
			),
			esc_url( admin_url( 'options-general.php?page=wp-mail-smtp#wp-mail-smtp-setting-row-from_name' ) )
		);
	}

	/**
	 * Display hint if WP Mail SMTP is forcing from email.
	 *
	 * @since 1.4.8
	 *
	 * @param string $after Text displayed after setting.
	 *
	 * @return string
	 */
	public function from_email_after( $after ) {

		if ( ! $this->options->get( 'mail', 'from_email_force' ) ) {
			return $after;
		}

		return sprintf(
			wp_kses( /* translators: %s - URL WP Mail SMTP settings. */
				__( 'This setting is disabled because you have the "Force From Email" setting enabled in the <a href="%s" target="_blank">WP Mail SMTP</a> plugin.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
					],
				]
			),
			esc_url( admin_url( 'options-general.php?page=wp-mail-smtp#wp-mail-smtp-setting-row-from_email' ) )
		);
	}
}
