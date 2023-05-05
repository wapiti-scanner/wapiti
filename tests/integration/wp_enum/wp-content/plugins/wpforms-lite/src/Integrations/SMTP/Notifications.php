<?php

namespace WPForms\Integrations\SMTP;

use WPForms\Integrations\IntegrationInterface;

/**
 * Notifications class.
 *
 * @since 1.7.6
 */
class Notifications implements IntegrationInterface {

	/**
	 * Determine if the class is allowed to load.
	 *
	 * @since 1.7.6
	 *
	 * @return bool
	 */
	public function allow_load() {

		return wpforms_is_admin_page( 'builder' ) || wpforms_is_admin_ajax();
	}

	/**
	 * Load the class.
	 *
	 * @since 1.7.6
	 */
	public function load() {

		$this->hooks();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.6
	 */
	private function hooks() {

		add_filter( 'wpforms_builder_notifications_sender_address_settings', [ $this, 'change_from_email_settings' ], 10, 3 );
		add_action( 'wp_ajax_wpforms_builder_notification_from_email_validate', [ $this, 'notification_from_email_validate' ] );
		add_filter( 'wpforms_builder_strings', [ $this, 'form_builder_strings' ], 10, 2 );
	}

	/**
	 * Validate email.
	 *
	 * @since 1.8.1
	 */
	public function notification_from_email_validate() {

		check_ajax_referer( 'wpforms-builder', 'nonce' );

		// Before checking if $_POST['email'] is valid email, we need to check if smart tag is used and return its value.
		$email = ! empty( $_POST['email'] ) ? sanitize_text_field( wp_unslash( $_POST['email'] ) ) : '';
		$email = $email ? sanitize_email( wpforms_process_smart_tags( $email, [], [], '' ) ) : '';

		if ( ! is_email( $email ) ) {
			wp_send_json_error(
				sprintf(
					'<div class="wpforms-alert wpforms-alert-warning wpforms-alert-warning-wide">%s</div>',
					__( 'Please enter a valid email address. Your notifications won\'t be sent if the field is not filled in correctly.', 'wpforms-lite' )
				)
			);
		}

		if ( ! $this->email_domain_matches_site_domain( $email ) ) {
			wp_send_json_error( $this->get_warning_message() );
		}

		wp_send_json_success();
	}

	/**
	 * Append additional strings for form builder.
	 *
	 * @since 1.8.1
	 *
	 * @param array  $strings List of strings.
	 * @param object $form    Current form object.
	 *
	 * @return array
	 */
	public function form_builder_strings( $strings, $form ) {

		$strings['allow_only_one_email'] = esc_html__( 'Notifications can only use 1 From Email. Please do not enter multiple addresses.', 'wpforms-lite' );

		return $strings;
	}

	/**
	 * Add warning message when email doesn't match site domain.
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

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		/** This filter is documented in lite/wpforms-lite.php */
		$from_email_after = apply_filters( 'wpforms_builder_notifications_from_email_after', '', $form_data, $id );
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		if ( ! empty( $from_email_after ) ) {
			$default = [
				'readonly'    => true,
				'after'       => '<div class="wpforms-alert wpforms-alert-warning">' . $from_email_after . '</div>',
				'input_class' => 'wpforms-disabled',
				'class'       => 'from-email wpforms-panel-field-warning',
			];
		} else {
			$default = [
				'class'   => 'from-email js-wpforms-from-email-validation',
				'tooltip' => esc_html__( 'Notifications can only use 1 From Email. Please do not enter multiple addresses.', 'wpforms-lite' ),
			];
		}

		$args = wp_parse_args( $args, $default );

		$email = empty( $form_data['settings']['notifications'][ $id ]['sender_address'] ) ? '{admin_email}' : $form_data['settings']['notifications'][ $id ]['sender_address'];

		if ( $this->email_domain_matches_site_domain( $email ) || $this->has_active_smtp_plugin() ) {
			return $args;
		}

		$args['after']  = $this->get_warning_message();
		$args['class'] .= ' wpforms-panel-field-warning';

		return $args;
	}

	/**
	 * Get warning message.
	 *
	 * @since 1.8.1
	 *
	 * @return string
	 */
	private function get_warning_message() {

		$site_domain = wp_parse_url( get_bloginfo( 'wpurl' ) )['host'];

		$email_does_not_match_text = sprintf( /* translators: %1$s - WordPress site domain. */
			__( 'The current \'From Email\' address does not match your website domain name (%1$s). This can cause your notification emails to be blocked or marked as spam.', 'wpforms-lite' ),
			esc_html( $site_domain )
		);

		$install_wp_mail_smtp_text = sprintf(
			wp_kses( /* translators: %1$s - WP Mail SMTP install page URL. */
				__(
					'We strongly recommend that you install the free <a href="%1$s" target="_blank">WP Mail SMTP</a> plugin! The Setup Wizard makes it easy to fix your emails.',
					'wpforms-lite'
				),
				[
					'a' => [
						'href'   => [],
						'target' => [],
					],
				]
			),
			esc_url( admin_url( 'admin.php?page=wpforms-smtp' ) )
		);

		$address_match_text = sprintf( /* translators: %1$s - WordPress site domain. */
			__( 'Alternately, try using a From Address that matches your website domain (no-reply@%1$s).', 'wpforms-lite' ),
			esc_html( $site_domain )
		);

		$fix_email_delivery_text = sprintf(
			wp_kses( /* translators: %1$s - Fixing email delivery issues doc URL. */
				__(
					'Please check out our <a href="%1$s" target="_blank" rel="noopener noreferrer">doc on fixing email delivery issues</a> for more details.',
					'wpforms-lite'
				),
				[
					'a' => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
				]
			),
			esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-fix-wordpress-contact-form-not-sending-email-with-smtp/', 'Builder Notifications', 'Delivery Issues Documentation' ) )
		);

		return sprintf(
			'<div class="wpforms-alert wpforms-alert-warning wpforms-alert-warning-wide"> <p>%1$s</p> <p>%2$s</p> <p>%3$s</p> <p>%4$s</p> </div>',
			$email_does_not_match_text,
			$install_wp_mail_smtp_text,
			$address_match_text,
			$fix_email_delivery_text
		);
	}

	/**
	 * Check if the domain name in an email address matches the WordPress site domain.
	 *
	 * @since 1.7.6
	 *
	 * @param string $email The email address to check against the WordPress site domain.
	 *
	 * @return bool
	 */
	private function email_domain_matches_site_domain( $email ) {

		// Process smart tags if they are used as a value.
		$email = wpforms_process_smart_tags( $email, [] );

		// Skip processing when email is empty or does not set.
		// e.g. {field_id="3"} which we don't have at the moment.
		if ( empty( $email ) ) {
			return true;
		}

		$email_domain = substr( strrchr( $email, '@' ), 1 );
		$site_domain  = wp_parse_url( get_bloginfo( 'wpurl' ) )['host'];

		// Check if From email domain ends with site domain.
		return ! empty( $email_domain ) && preg_match( "/\b{$email_domain}$/", $site_domain ) === 1;
	}

	/**
	 * Check if the site has any active SMTP plugins.
	 *
	 * @since 1.7.6
	 *
	 * @return bool
	 */
	private function has_active_smtp_plugin() {

		// List of plugins from \WPMailSMTP\Conflicts.
		$smtp_plugin_list = [
			'branda-white-labeling/ultimate-branding.php',
			'bws-smtp/bws-smtp.php',
			'cimy-swift-smtp/cimy_swift_smtp.php',
			'disable-emails/disable-emails.php',
			'easy-wp-smtp/easy-wp-smtp.php',
			'fluent-smtp/fluent-smtp.php',
			'gmail-smtp/main.php',
			'mailgun/mailgun.php',
			'my-smtp-wp/my-smtp-wp.php',
			'post-smtp/postman-smtp.php',
			'postman-smtp/postman-smtp.php',
			'postmark-approved-wordpress-plugin/postmark.php',
			'sar-friendly-smtp/sar-friendly-smtp.php',
			'sendgrid-email-delivery-simplified/wpsendgrid.php',
			'smtp-mail/index.php',
			'smtp-mailer/main.php',
			'sparkpost/wordpress-sparkpost.php',
			'turbosmtp/turbo-smtp-plugin.php',
			'woocommerce-sendinblue-newsletter-subscription/woocommerce-sendinblue.php',
			'wp-amazon-ses-smtp/wp-amazon-ses.php',
			'wp-easy-smtp/wp-easy-smtp.php',
			'wp-gmail-smtp/wp-gmail-smtp.php',
			'wp-html-mail/wp-html-mail.php',
			'wp-mail-bank/wp-mail-bank.php',
			'wp-mail-booster/wp-mail-booster.php',
			'wp-mail-smtp-mailer/wp-mail-smtp-mailer.php',
			'wp-mail-smtp-pro/wp_mail_smtp.php',
			'wp-mail-smtp/wp_mail_smtp.php',
			'wp-mailgun-smtp/wp-mailgun-smtp.php',
			'wp-offload-ses/wp-offload-ses.php',
			'wp-sendgrid-smtp/wp-sendgrid-smtp.php',
			'wp-ses/wp-ses.php',
			'wp-smtp/wp-smtp.php',
			'wp-yahoo-smtp/wp-yahoo-smtp.php',
		];

		foreach ( $smtp_plugin_list as $smtp_plugin ) {
			if ( is_plugin_active( $smtp_plugin ) ) {
				return true;
			}
		}

		return false;
	}
}
