<?php

use WPForms\Lite\Integrations\LiteConnect\LiteConnect;
use WPForms\Lite\Integrations\LiteConnect\Integration as LiteConnectIntegration;

/**
 * WPForms Lite. Load Lite-specific features/functionality.
 *
 * @since 1.2.0
 */
class WPForms_Lite {

	/**
	 * Primary class constructor.
	 *
	 * @since 1.2.2
	 */
	public function __construct() {

		$this->includes();

		add_action( 'wpforms_install', [ $this, 'install' ] );
		add_action( 'wpforms_form_settings_notifications', [ $this, 'form_settings_notifications' ], 8, 1 );
		add_action( 'wpforms_form_settings_confirmations', [ $this, 'form_settings_confirmations' ] );
		add_action( 'wpforms_builder_enqueues_before', [ $this, 'builder_enqueues' ] );
		add_action( 'wpforms_admin_page', [ $this, 'entries_page' ] );
		add_action( 'wpforms_admin_settings_after', [ $this, 'settings_cta' ] );
		add_action( 'wp_ajax_wpforms_lite_settings_upgrade', [ $this, 'settings_cta_dismiss' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'admin_enqueues' ] );
		add_filter( 'wpforms_helpers_templates_get_theme_template_paths', [ $this, 'add_templates' ] );

		// Entries count logging for WPForms Lite.
		add_action( 'wpforms_process_entry_save', [ $this, 'entry_submit' ], 10, 4 );
		add_action( 'wpforms_process_entry_save', [ $this, 'update_entry_count' ], 10, 3 );

		// Upgrade to Pro WPForms menu bar item.
		add_action( 'admin_bar_menu', [ $this, 'upgrade_to_pro_menu' ], 1000 );
	}

	/**
	 * Include files.
	 *
	 * @since 1.0.0
	 */
	private function includes() {
	}

	/**
	 * Form notification settings, supports multiple notifications.
	 *
	 * @since 1.2.3
	 *
	 * @param object $settings
	 */
	public function form_settings_notifications( $settings ) {

		$cc         = wpforms_setting( 'email-carbon-copy', false );
		$from_email = '{admin_email}';
		$from_name  = sanitize_text_field( get_option( 'blogname' ) );

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		/**
		 * Allow filtering of text after the `From Name` field.
		 *
		 * @since 1.2.3
		 * @since 1.7.6 Added $form_data and $id arguments.
		 *
		 * @param string $value     Value to be filtered.
		 * @param array  $form_data Form data.
		 * @param int    $id        Notification ID.
		 */
		$from_name_after = apply_filters( 'wpforms_builder_notifications_from_name_after', '', $settings->form_data, 1 );

		/**
		 * Allow filtering of text after the `From Email` field.
		 *
		 * @since 1.2.3
		 * @since 1.7.6 Added $form_data and $id arguments.
		 *
		 * @param array $value     Value to be filtered.
		 * @param array $form_data Form data.
		 * @param int   $id        Notification ID.
		 */
		$from_email_after = apply_filters( 'wpforms_builder_notifications_from_email_after', '', $settings->form_data, 1 );
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		// Handle backwards compatibility.
		if ( empty( $settings->form_data['settings']['notifications'] ) ) {
			/* translators: %s - form name. */
			$settings->form_data['settings']['notifications'][1]['subject']        = ! empty( $settings->form_data['settings']['notification_subject'] ) ? $settings->form_data['settings']['notification_subject'] : sprintf( esc_html__( 'New %s Entry', 'wpforms-lite' ), $settings->form->post_title );
			$settings->form_data['settings']['notifications'][1]['email']          = ! empty( $settings->form_data['settings']['notification_email'] ) ? $settings->form_data['settings']['notification_email'] : '{admin_email}';
			$settings->form_data['settings']['notifications'][1]['sender_name']    = ! empty( $settings->form_data['settings']['notification_fromname'] ) ? $settings->form_data['settings']['notification_fromname'] : $from_name;
			$settings->form_data['settings']['notifications'][1]['sender_address'] = ! empty( $settings->form_data['settings']['notification_fromaddress'] ) ? $settings->form_data['settings']['notification_fromaddress'] : $from_email;
			$settings->form_data['settings']['notifications'][1]['replyto']        = ! empty( $settings->form_data['settings']['notification_replyto'] ) ? $settings->form_data['settings']['notification_replyto'] : '';
		}

		$id = 1;

		echo '<div class="wpforms-panel-content-section-title">';
			echo '<span id="wpforms-builder-settings-notifications-title">';
				esc_html_e( 'Notifications', 'wpforms-lite' );
			echo '</span>';
			echo '<button class="wpforms-builder-settings-block-add education-modal"
					data-utm-content="Multiple notifications"
					data-name="' . esc_attr__( 'Multiple notifications', 'wpforms-lite' ) . '">';
				esc_html_e( 'Add New Notification', 'wpforms-lite' );
			echo '</button>';
		echo '</div>';

		$dismissed = get_user_meta( get_current_user_id(), 'wpforms_dismissed', true );

		if ( empty( $dismissed['edu-builder-notifications-description'] ) ) {
			echo '<div class="wpforms-panel-content-section-description wpforms-dismiss-container wpforms-dismiss-out">';
			echo '<button type="button" class="wpforms-dismiss-button" title="' . esc_attr__( 'Dismiss this message.', 'wpforms-lite' ) . '" data-section="builder-notifications-description"></button>';
			echo '<p>';
			printf(
				wp_kses( /* translators: %s - Link to the WPForms.com doc article. */
					__( 'Notifications are emails sent when a form is submitted. By default, these emails include entry details. For setup and customization options, including a video overview, please <a href="%s" target="_blank" rel="noopener noreferrer">see our tutorial</a>.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'rel'    => [],
							'target' => [],
						],
					]
				),
				esc_url( wpforms_utm_link( 'https://wpforms.com/docs/setup-form-notification-wpforms/', 'Builder Notifications',  'Form Notifications Documentation' ) )
			);
			echo '</p>';
			echo '<p>';
			printf(
				wp_kses( /* translators: 1$s, %2$s - Links to the WPForms.com doc articles. */
					__( 'After saving these settings, be sure to <a href="%1$s" target="_blank" rel="noopener noreferrer">test a form submission</a>. This lets you see how emails will look, and to ensure that they <a href="%2$s" target="_blank" rel="noopener noreferrer">are delivered successfully</a>.', 'wpforms-lite' ),
					[
						'a'  => [
							'href'   => [],
							'rel'    => [],
							'target' => [],
						],
						'br' => [],
					]
				),
				esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-properly-test-your-wordpress-forms-before-launching-checklist/', 'Builder Notifications', 'Testing A Form Documentation' ) ),
				esc_url( wpforms_utm_link( 'https://wpforms.com/docs/troubleshooting-email-notifications/', 'Builder Notifications', 'Troubleshoot Notifications Documentation' ) )
			);
			echo '</p>';
			echo '</div>';
		}

		wpforms_panel_field(
			'toggle',
			'settings',
			'notification_enable',
			$settings->form_data,
			esc_html__( 'Enable Notifications', 'wpforms-lite' )
		);
		?>

		<div class="wpforms-notification wpforms-builder-settings-block">

			<div class="wpforms-builder-settings-block-header">
				<span><?php esc_html_e( 'Default Notification', 'wpforms-lite' ); ?></span>
			</div>

			<div class="wpforms-builder-settings-block-content">

				<?php
				wpforms_panel_field(
					'text',
					'notifications',
					'email',
					$settings->form_data,
					esc_html__( 'Send To Email Address', 'wpforms-lite' ),
					[
						'default'    => '{admin_email}',
						'tooltip'    => esc_html__( 'Enter the email address to receive form entry notifications. For multiple notifications, separate email addresses with a comma.', 'wpforms-lite' ),
						'smarttags'  => [
							'type'   => 'fields',
							'fields' => 'email',
						],
						'parent'     => 'settings',
						'subsection' => $id,
						'class'      => 'email-recipient',
					]
				);
				if ( $cc ) :
					wpforms_panel_field(
						'text',
						'notifications',
						'carboncopy',
						$settings->form_data,
						esc_html__( 'CC', 'wpforms-lite' ),
						[
							'smarttags'  => [
								'type'   => 'fields',
								'fields' => 'email',
							],
							'parent'     => 'settings',
							'subsection' => $id,
						]
					);
				endif;
				wpforms_panel_field(
					'text',
					'notifications',
					'subject',
					$settings->form_data,
					esc_html__( 'Email Subject Line', 'wpforms-lite' ),
					[
						/* translators: %s - form name. */
						'default'    => sprintf( esc_html__( 'New Entry: %s', 'wpforms-lite' ), $settings->form->post_title ),
						'smarttags'  => [
							'type' => 'all',
						],
						'parent'     => 'settings',
						'subsection' => $id,
					]
				);
				wpforms_panel_field(
					'text',
					'notifications',
					'sender_name',
					$settings->form_data,
					esc_html__( 'From Name', 'wpforms-lite' ),
					// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
					/**
					 * Allow modifying the "From Name" field settings in the builder on Settings > Notifications panel.
					 *
					 * @since 1.7.6
					 *
					 * @param array $args      Field settings.
					 * @param array $form_data Form data.
					 * @param int   $id        Notification ID.
					 */
					apply_filters(
						'wpforms_builder_notifications_sender_name_settings',
						[
							'default'    => $from_name,
							'smarttags'  => [
								'type'   => 'fields',
								'fields' => 'name,text',
							],
							'parent'     => 'settings',
							'subsection' => $id,
							'readonly'   => ! empty( $from_name_after ),
							'after'      => ! empty( $from_name_after ) ? '<div class="wpforms-alert wpforms-alert-warning">' . $from_name_after . '</div>' : '',
							'class'      => ! empty( $from_name_after ) ? 'wpforms-panel-field-warnings' : '',
						],
						$settings->form_data,
						$id
					)
					// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
				);
				wpforms_panel_field(
					'text',
					'notifications',
					'sender_address',
					$settings->form_data,
					esc_html__( 'From Email', 'wpforms-lite' ),
					// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
					/**
					 * Allow modifying the "From Email" field settings in the builder on Settings > Notifications panel.
					 *
					 * @since 1.7.6
					 *
					 * @param array $args      Field settings.
					 * @param array $form_data Form data.
					 * @param int   $id        Notification ID.
					 */
					apply_filters(
						'wpforms_builder_notifications_sender_address_settings',
						[
							'default'    => $from_email,
							'smarttags'  => [
								'type'   => 'fields',
								'fields' => 'email',
							],
							'parent'     => 'settings',
							'subsection' => $id,
						],
						$settings->form_data,
						$id
					)
					// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
				);
				wpforms_panel_field(
					'text',
					'notifications',
					'replyto',
					$settings->form_data,
					esc_html__( 'Reply-To', 'wpforms-lite' ),
					[
						'tooltip'    => esc_html(
							sprintf( /* translators: %s - <email@example.com>. */
								__( 'Enter the email address or email address with recipient\'s name in "First Last %s" format.', 'wpforms-lite' ),
								// &#8203 is a zero-width space character. Without it, Tooltipster thinks it's an HTML tag
								// and closes it at the end of the string, hiding everything after this value.
								'<&#8203;email@example.com&#8203;>'
							)
						),
						'smarttags'  => [
							'type'   => 'fields',
							'fields' => 'email,name',
						],
						'parent'     => 'settings',
						'subsection' => $id,
					]
				);
				wpforms_panel_field(
					'textarea',
					'notifications',
					'message',
					$settings->form_data,
					esc_html__( 'Email Message', 'wpforms-lite' ),
					[
						'rows'       => 6,
						'default'    => '{all_fields}',
						'smarttags'  => [
							'type' => 'all',
						],
						'parent'     => 'settings',
						'subsection' => $id,
						'class'      => 'email-msg',
						'after'      => '<p class="note">' .
										sprintf(
											/* translators: %s - {all_fields} Smart Tag. */
											esc_html__( 'To display all form fields, use the %s Smart Tag.', 'wpforms-lite' ),
											'<code>{all_fields}</code>'
										) .
										'</p>',
					]
				);

				/**
				 * Fires immediately after notification block on lite version.
				 *
				 * @since 1.7.7
				 *
				 * @param array $settings Current confirmation data.
				 * @param int   $id       Notification id.
				 */
				do_action( 'wpforms_lite_form_settings_notifications_block_content_after', $settings, $id );
				?>
			</div>
		</div>

		<?php
		do_action( 'wpforms_builder_settings_notifications_after', 'notifications', $settings );

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

		/**
		 * Fires after notification block.
		 *
		 * @since 1.7.6
		 *
		 * @param array $settings Current confirmation data.
		 * @param int   $id       Notification id.
		 */
		do_action( 'wpforms_form_settings_notifications_single_after', $settings, 1 );

		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName
	}

	/**
	 * Lite admin scripts and styles.
	 *
	 * @since 1.5.7
	 */
	public function admin_enqueues() {

		if ( ! wpforms_is_admin_page() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		// Admin styles.
		wp_enqueue_style(
			'wpforms-lite-admin',
			WPFORMS_PLUGIN_URL . "assets/lite/css/admin{$min}.css",
			[],
			WPFORMS_VERSION
		);
	}

	/**
	 * Form confirmation settings, supports multiple confirmations.
	 *
	 * @since 1.4.8
	 *
	 * @param WPForms_Builder_Panel_Settings $settings Builder panel settings.
	 */
	public function form_settings_confirmations( $settings ) {

		wp_enqueue_editor();

		// Handle backwards compatibility.
		if ( empty( $settings->form_data['settings']['confirmations'] ) ) {
			$settings->form_data['settings']['confirmations'][1]['type']           = ! empty( $settings->form_data['settings']['confirmation_type'] ) ? $settings->form_data['settings']['confirmation_type'] : 'message';
			$settings->form_data['settings']['confirmations'][1]['message']        = ! empty( $settings->form_data['settings']['confirmation_message'] ) ? $settings->form_data['settings']['confirmation_message'] : esc_html__( 'Thanks for contacting us! We will be in touch with you shortly.', 'wpforms-lite' );
			$settings->form_data['settings']['confirmations'][1]['message_scroll'] = ! empty( $settings->form_data['settings']['confirmation_message_scroll'] ) ? $settings->form_data['settings']['confirmation_message_scroll'] : 1;
			$settings->form_data['settings']['confirmations'][1]['page']           = ! empty( $settings->form_data['settings']['confirmation_page'] ) ? $settings->form_data['settings']['confirmation_page'] : '';
			$settings->form_data['settings']['confirmations'][1]['redirect']       = ! empty( $settings->form_data['settings']['confirmation_redirect'] ) ? $settings->form_data['settings']['confirmation_redirect'] : '';
		}
		$field_id = 1;

		echo '<div class="wpforms-panel-content-section-title">';
			esc_html_e( 'Confirmations', 'wpforms-lite' );
			echo '<button class="wpforms-builder-settings-block-add education-modal"
					data-utm-content="Multiple confirmations"
					data-name="' . esc_attr__( 'Multiple confirmations', 'wpforms-lite' ) . '">';
				esc_html_e( 'Add New Confirmation', 'wpforms-lite' );
			echo '</button>';
		echo '</div>';
		?>

		<div class="wpforms-confirmation wpforms-builder-settings-block">

			<div class="wpforms-builder-settings-block-header">
				<span><?php esc_html_e( 'Default Confirmation', 'wpforms-lite' ); ?></span>
			</div>

			<div class="wpforms-builder-settings-block-content">

				<?php
				/**
				 * Fires before each confirmation to add custom fields.
				 *
				 * @since 1.6.9
				 *
				 * @param WPForms_Builder_Panel_Settings $settings Builder panel settings.
				 * @param int                            $field_id Field ID.
				 */
				do_action( 'wpforms_lite_form_settings_confirmations_single_before', $settings, $field_id );

				wpforms_panel_field(
					'select',
					'confirmations',
					'type',
					$settings->form_data,
					esc_html__( 'Confirmation Type', 'wpforms-lite' ),
					[
						'default'     => 'message',
						'options'     => [
							'message'  => esc_html__( 'Message', 'wpforms-lite' ),
							'page'     => esc_html__( 'Show Page', 'wpforms-lite' ),
							'redirect' => esc_html__( 'Go to URL (Redirect)', 'wpforms-lite' ),
						],
						'class'       => 'wpforms-panel-field-confirmations-type-wrap',
						'input_class' => 'wpforms-panel-field-confirmations-type',
						'parent'      => 'settings',
						'subsection'  => $field_id,
					]
				);
				wpforms_panel_field(
					'textarea',
					'confirmations',
					'message',
					$settings->form_data,
					esc_html__( 'Confirmation Message', 'wpforms-lite' ),
					[
						'default'     => esc_html__( 'Thanks for contacting us! We will be in touch with you shortly.', 'wpforms-lite' ),
						'tinymce'     => [
							'editor_height' => '200',
						],
						'input_id'    => 'wpforms-panel-field-confirmations-message-' . $field_id,
						'input_class' => 'wpforms-panel-field-confirmations-message',
						'parent'      => 'settings',
						'subsection'  => $field_id,
						'class'       => 'wpforms-panel-field-tinymce',
						'smarttags'   => [
							'type' => 'all',
						],
					]
				);
				wpforms_panel_field(
					'toggle',
					'confirmations',
					'message_scroll',
					$settings->form_data,
					esc_html__( 'Automatically scroll to the confirmation message', 'wpforms-lite' ),
					[
						'input_class' => 'wpforms-panel-field-confirmations-message_scroll',
						'parent'      => 'settings',
						'subsection'  => $field_id,
					]
				);

				wpforms_panel_field(
					'select',
					'confirmations',
					'page',
					$settings->form_data,
					esc_html__( 'Confirmation Page', 'wpforms-lite' ),
					[
						'class'       => 'wpforms-panel-field-confirmations-page-choicesjs-unflippable',
						'options'     => wpforms_builder_form_settings_confirmation_get_pages( $settings->form_data, $field_id ),
						'input_class' => 'wpforms-panel-field-confirmations-page',
						'parent'      => 'settings',
						'subsection'  => $field_id,
						'choicesjs'   => [
							'use_ajax'    => true,
							'callback_fn' => 'select_pages',
						],
					]
				);
				wpforms_panel_field(
					'text',
					'confirmations',
					'redirect',
					$settings->form_data,
					esc_html__( 'Confirmation Redirect URL', 'wpforms-lite' ) . ' <span class="required">*</span>',
					[
						'input_class' => 'wpforms-panel-field-confirmations-redirect',
						'parent'      => 'settings',
						'subsection'  => $field_id,
					]
				);

				/**
				 * Fires after each confirmation to add custom fields.
				 *
				 * @since 1.6.9
				 *
				 * @param WPForms_Builder_Panel_Settings $settings Builder panel settings.
				 * @param int                            $field_id Field ID.
				 */
				do_action( 'wpforms_lite_form_settings_confirmations_single_after', $settings, $field_id );
				?>
			</div>
		</div>

		<?php
		do_action( 'wpforms_builder_settings_confirmations_after', 'confirmations', $settings );
	}

	/**
	 * Load assets for lite version with the admin builder.
	 *
	 * @since 1.0.0
	 */
	public function builder_enqueues() {

		$min = wpforms_get_min_suffix();

		wp_enqueue_script(
			'wpforms-builder-lite',
			WPFORMS_PLUGIN_URL . "assets/lite/js/admin-builder-lite{$min}.js",
			[ 'jquery', 'jquery-confirm' ],
			WPFORMS_VERSION,
			false
		);

		$strings = [
			'disable_notifications' => sprintf(
				wp_kses( /* translators: %s - WPForms.com docs page URL. */
					__( 'You\'ve just turned off notification emails for this form. Since entries are not stored in WPForms Lite, notification emails are recommended for collecting entry details. For setup steps, <a href="%s" target="_blank" rel="noopener noreferrer">please see our notification tutorial</a>.', 'wpforms-lite' ),
					[
						'a' => [
							'href'   => [],
							'target' => [],
							'rel'    => [],
						],
					]
				),
				esc_url( wpforms_utm_link( 'https://wpforms.com/docs/setup-form-notification-wpforms/', 'Builder Notifications', 'Disable Notifications Alert' ) )
			),
		];

		$strings = apply_filters( 'wpforms_lite_builder_strings', $strings );

		wp_localize_script(
			'wpforms-builder-lite',
			'wpforms_builder_lite',
			$strings
		);
	}

	/**
	 * Display upgrade notice at the bottom on the plugin settings pages.
	 *
	 * @since 1.4.7
	 *
	 * @param string $view Current view inside the plugin settings page.
	 */
	public function settings_cta( $view ) {

		if ( get_option( 'wpforms_lite_settings_upgrade', false ) || apply_filters( 'wpforms_lite_settings_upgrade', false ) ) {
			return;
		}
		?>
		<div class="settings-lite-cta">
			<a href="#" class="dismiss" title="<?php esc_attr_e( 'Dismiss this message', 'wpforms-lite' ); ?>"><i class="fa fa-times-circle" aria-hidden="true"></i></a>
			<h5><?php esc_html_e( 'Get WPForms Pro and Unlock all the Powerful Features', 'wpforms-lite' ); ?></h5>
			<p><?php esc_html_e( 'Thanks for being a loyal WPForms Lite user. Upgrade to WPForms Pro to unlock all the awesome features and experience why WPForms is consistently rated the best WordPress form builder.', 'wpforms-lite' ); ?></p>
			<p>
				<?php
				printf(
					wp_kses( /* translators: %s - star icons. */
						__( 'We know that you will truly love WPForms. It has over 12,000+ five star ratings (%s) and is active on over 5 million websites.', 'wpforms-lite' ),
						[
							'i' => [
								'class'       => [],
								'aria-hidden' => [],
							],
						]
					),
					str_repeat( '<i class="fa fa-star" aria-hidden="true"></i>', 5 ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
				?>
			</p>
			<h6><?php esc_html_e( 'Pro Features:', 'wpforms-lite' ); ?></h6>
			<div class="list">
				<ul>
					<li><?php esc_html_e( '600+ customizable form templates', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Store and manage form entries in WordPress', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Unlock all fields & features, including Rich Text & conditional logic', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Make Surveys and Polls and create reports', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Accept user-submitted content with the Post Submissions addon', 'wpforms-lite' ); ?></li>
				</ul>
				<ul>
					<li><?php esc_html_e( '5000+ integrations with marketing and payment services', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Let users Save and Resume submissions to prevent abandonment', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Take payments with PayPal Commerce, Stripe, Square, Authorize.Net, and PayPal Standard', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Collect signatures, geolocation data, and file uploads', 'wpforms-lite' ); ?></li>
					<li><?php esc_html_e( 'Create user registration and login forms', 'wpforms-lite' ); ?></li>
				</ul>
			</div>
			<p>
				<?php $utm_content = ucwords( $view ) . ' Tab'; ?>
				<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'settings-upgrade', $utm_content ) ); ?>" target="_blank" rel="noopener noreferrer">
					<?php esc_html_e( 'Get WPForms Pro Today and Unlock all the Powerful Features »', 'wpforms-lite' ); ?>
				</a>
			</p>
			<p>
				<?php
				echo wp_kses(
					__( '<strong>Bonus:</strong> WPForms Lite users get <span class="green">50% off regular price</span>, automatically applied at checkout.', 'wpforms-lite' ),
					[
						'strong' => [],
						'span'   => [
							'class' => [],
						],
					]
				);
				?>
			</p>
		</div>
		<script type="text/javascript">
			jQuery( function ( $ ) {
				$( document ).on( 'click', '.settings-lite-cta .dismiss', function ( event ) {
					event.preventDefault();
					$.post( ajaxurl, {
						action: 'wpforms_lite_settings_upgrade'
					} );
					$( '.settings-lite-cta' ).remove();
				} );
			} );
		</script>
		<?php
	}

	/**
	 * Dismiss upgrade notice at the bottom on the plugin settings pages.
	 *
	 * @since 1.4.7
	 */
	public function settings_cta_dismiss() {

		if ( ! wpforms_current_user_can() ) {
			wp_send_json_error();
		}

		update_option( 'wpforms_lite_settings_upgrade', time() );

		wp_send_json_success();
	}

	/**
	 * Notify user that entries is a pro feature.
	 *
	 * @since 1.0.0
	 */
	public function entries_page() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'wpforms-entries' ) {
			return;
		}

		$is_lite_connect_enabled = LiteConnect::is_enabled();
		$is_lite_connect_allowed = LiteConnect::is_allowed();
		?>

		<style>
			.wpforms-admin-content {
				-webkit-filter: blur(3px);
				-moz-filter: blur(3px);
				-ms-filter: blur(3px);
				-o-filter: blur(3px);
				filter: blur(3px);
				user-select: none;
				-webkit-user-select: none;
				pointer-events: none;
			}

			.wpforms-admin-content a {
				pointer-events: none;
				cursor: default;
			}

			.ie-detected {
				position: absolute;
				top: 0;
				width: 100%;
				height: 100%;
				left: 0;
				background-color: #f1f1f1;
				opacity: 0.65;
				z-index: 10;
			}

			.wpforms-admin-content,
			.wpforms-admin-content-wrap {
				position: relative;
			}

			.entries-modal {
				text-align: center;
				width: 730px;
				box-shadow: 0 0 60px 30px rgba(0, 0, 0, 0.15);
				border-radius: 6px;
				position: absolute;
				top: 75px;
				left: 50%;
				margin: 0 auto 0 -365px;
				z-index: 100;
				overflow: hidden;
			}

			.entries-modal *,
			.entries-modal *::before,
			.entries-modal *::after {
				-webkit-box-sizing: border-box;
				-moz-box-sizing: border-box;
				box-sizing: border-box;
			}

			.entries-modal h2 {
				font-size: 20px;
				margin: 0 0 16px 0;
				padding: 0;
			}

			.entries-modal p {
				font-size: 16px;
				line-height: 24px;
				color: #777777;
				margin: 0 0 30px 0;
				padding: 0;
			}

			.entries-modal-content-top-notice {
				padding: 10px;
				text-align: center;
				font-style: normal;
				font-weight: normal;
				font-size: 15px;
				line-height: 24px;
				color: #444444;
				background: #fcf9e8;
			}

			.entries-modal-content-top-notice .wpforms-icon {
				width: 18px;
				height: 16px;
				background-image: url('<?php echo esc_url( WPFORMS_PLUGIN_URL ); ?>assets/images/exclamation-triangle-orange.svg');
				background-repeat: no-repeat;
				background-size: 18px 16px;
				display: inline-block;
				margin-right: 10px;
				vertical-align: -2px;
			}

			.entries-modal-content {
				background-color: #ffffff;
				border-radius: 3px 3px 0 0;
				padding: 40px;
			}

			.entries-modal ul {
				float: left;
				width: 50%;
				margin: 0;
				padding: 0 0 0 30px;
				text-align: left;
			}

			.entries-modal li {
				color: #777777;
				font-size: 16px;
				line-height: 19px;
				padding: 6px 0;
			}

			.entries-modal li .fa {
				color: #2a9b39;
				margin: 0 8px 0 0;
			}

			.entries-modal-button {
				border-radius: 0 0 3px 3px;
				padding: 30px;
				background: #f5f5f5;
				text-align: center;
			}

			.entries-modal-button p {
				margin: 20px 0 0 0;
				font-size: 15px;
				line-height: 18px;
				text-align: center;
			}

			.entries-modal-button p span {
				display: inline-block;
				margin-left: 20px;
				vertical-align: bottom;
				font-size: 14px;
				line-height: 17px;
			}

			.entries-modal-button p .wpforms-toggle-control .wpforms-toggle-control-label {
				max-width: none;
			}

			.entries-modal-button .entries-modal-button-before {
				line-height: 24px;
				margin: 0 0 20px 0;
				color: #444444;
			}

			#wpforms-entries-list .entries .column-indicators > a {
				float: left;
			}
		</style>

		<script type="text/javascript">
			jQuery( function ( $ ) {
				var userAgent = window.navigator.userAgent,
					onlyIEorEdge = /msie\s|trident\/|edge\//i.test( userAgent ) && ! ! (document.uniqueID || window.MSInputMethodContext),
					checkVersion = (onlyIEorEdge && + (/(edge\/|rv:|msie\s)([\d.]+)/i.exec( userAgent )[ 2 ])) || NaN;
				if ( ! isNaN( checkVersion ) ) {
					$( '#ie-wrap' ).addClass( 'ie-detected' );
				}
			} );
		</script>

		<div id="wpforms-entries-list" class="wrap wpforms-admin-wrap wpforms-entries-list-upgrade">
			<h1 class="page-title">Entries</h1>
			<div class="wpforms-admin-content-wrap">

				<div class="entries-modal">
					<?php if ( ! $is_lite_connect_enabled ) : ?>
						<div class="entries-modal-content-top-notice">
							<i class="wpforms-icon"></i><?php esc_html_e( 'Form entries are not stored in WPForms Lite.', 'wpforms-lite' ); ?>
						</div>
					<?php endif; ?>
					<div class="entries-modal-content">
						<h2>
							<?php esc_html_e( 'View and Manage Your Form Entries inside WordPress', 'wpforms-lite' ); ?>
						</h2>
						<p>
							<?php esc_html_e( 'Once you upgrade to WPForms Pro, all future form entries will be stored in your WordPress database and displayed on this Entries screen.', 'wpforms-lite' ); ?>
						</p>
						<div class="wpforms-clear">
							<ul class="left">
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'View Entries in Dashboard', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Export Entries in a CSV File', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Add Notes / Comments', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Save Favorite Entries', 'wpforms-lite' ); ?></li>
							</ul>
							<ul class="right">
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Mark Read / Unread', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Print Entries', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'Resend Notifications', 'wpforms-lite' ); ?></li>
								<li><i class="fa fa-check" aria-hidden="true"></i> <?php esc_html_e( 'See Geolocation Data', 'wpforms-lite' ); ?></li>
							</ul>
						</div>
					</div>
					<div class="entries-modal-button">
						<?php if ( $is_lite_connect_enabled && $is_lite_connect_allowed ) : ?>

							<p class="entries-modal-button-before">
							<?php
								$entries_count = LiteConnectIntegration::get_new_entries_count();
								$enabled_since = LiteConnectIntegration::get_enabled_since();

								printf(
									'<strong>' . esc_html( /* translators: %d - Backed up entries count. */
										_n(
											'%d entry has been backed up',
											'%d entries have been backed up',
											$entries_count,
											'wpforms-lite'
										)
									) . '</strong>',
									absint( $entries_count )
								);

								if ( ! empty( $enabled_since ) ) {
									echo ' ';
									printf(
										/* translators: %s - Time when Lite Connect was enabled. */
										esc_html__( 'since you enabled Lite Connect on %s', 'wpforms-lite' ),
										esc_html( date_i18n( 'M j, Y', $enabled_since + get_option( 'gmt_offset' ) * 3600 ) )
									);
								}
							// phpcs:ignore Squiz.PHP.EmbeddedPhp.ContentAfterEnd
							?>.</p>
							<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'entries', 'Upgrade to WPForms Pro & Restore Form Entries Button' ) ); ?>" class="wpforms-btn wpforms-btn-lg wpforms-btn-orange wpforms-upgrade-modal" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Upgrade to WPForms Pro & Restore Form Entries', 'wpforms-lite' ); ?>
							</a>

						<?php else : ?>

							<a href="<?php echo esc_url( wpforms_admin_upgrade_link( 'entries', 'Upgrade to WPForms Pro Now Button' ) ); ?>" class="wpforms-btn wpforms-btn-lg wpforms-btn-orange wpforms-upgrade-modal" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Upgrade to WPForms Pro Now', 'wpforms-lite' ); ?>
							</a>

						<?php endif; ?>
					</div>
				</div>

				<div class="wpforms-admin-content">
					<div id="ie-wrap"></div>
					<div class="form-details wpforms-clear">
						<span class="form-details-sub">Select Form</span>
						<h3 class="form-details-title">
							Contact Us
							<div class="form-selector">
								<a href="#" title="Open form selector" class="toggle dashicons dashicons-arrow-down-alt2"></a>
								<div class="form-list" style="display: none;">
									<ul>
										<li></li>
									</ul>
								</div>
							</div>
						</h3>
						<div class="form-details-actions">
							<a href="#" class="form-details-actions-edit"><span class="dashicons dashicons-edit"></span> Edit This Form</a>
							<a href="#" class="form-details-actions-preview" target="_blank" rel="noopener noreferrer"><span class="dashicons dashicons-visibility"></span> Preview Form</a>
							<a href="#" class="form-details-actions-export"><span class="dashicons dashicons-migrate"></span> Export All (CSV)</a>
							<a href="#" class="form-details-actions-read"><span class="dashicons dashicons-marker"></span> Mark All Read</a>
						</div>
					</div>
					<form id="wpforms-entries-table">
						<ul class="subsubsub">
							<li class="all"><a href="#" class="current">All&nbsp;<span class="count">(<span class="total-num">10</span>)</span></a> |</li>
							<li class="unread"><a href="#">Unread&nbsp;<span class="count">(<span class="unread-num">10</span>)</span></a> |</li>
							<li class="starred"><a href="#">Starred&nbsp;<span class="count">(<span class="starred-num">0</span>)</span></a></li>
						</ul>
						<div class="tablenav top">
							<div class="alignleft actions bulkactions">
								<label for="bulk-action-selector-top" class="screen-reader-text">Select bulk action</label>
								<select name="action" id="bulk-action-selector-top">
									<option value="-1">Bulk Actions</option>
								</select>
								<input type="submit" id="doaction" class="button action" value="Apply">
							</div>
							<div class="tablenav-pages one-page">
								<span class="displaying-num">10 items</span>
								<span class="pagination-links">
									<span class="tablenav-pages-navspan" aria-hidden="true">«</span>
									<span class="tablenav-pages-navspan" aria-hidden="true">‹</span>
									<span class="paging-input">
										<label for="current-page-selector" class="screen-reader-text">Current Page</label>
										<input class="current-page" id="current-page-selector" type="text" name="paged" value="1" size="1" aria-describedby="table-paging">
										<span class="tablenav-paging-text"> of <span class="total-pages">1</span></span>
									</span>
									<span class="tablenav-pages-navspan" aria-hidden="true">›</span>
									<span class="tablenav-pages-navspan" aria-hidden="true">»</span>
								</span>
							</div>
							<br class="clear">
						</div>
						<table class="wp-list-table widefat fixed striped entries">
							<thead>
								<tr>
									<td id="cb" class="manage-column column-cb check-column">
										<label class="screen-reader-text" for="cb-select-all-1">Select All</label>
										<input id="cb-select-all-1" type="checkbox">
									</td>
									<th scope="col" id="indicators" class="manage-column column-indicators column-primary"></th>
									<th scope="col" id="wpforms_field_0" class="manage-column column-wpforms_field_0">Name</th>
									<th scope="col" id="wpforms_field_1" class="manage-column column-wpforms_field_1">Email</th>
									<th scope="col" id="wpforms_field_2" class="manage-column column-wpforms_field_2">Comment or Message</th>
									<th scope="col" id="date" class="manage-column column-date sortable desc">
										<a href="#"><span>Date</span><span class="sorting-indicator"></span></a>
									</th>
									<th scope="col" id="actions" class="manage-column column-actions">Actions</th>
								</tr>
							</thead>
							<tbody id="the-list" data-wp-lists="list:entry">
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1088"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1088" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1088" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">David Wells</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">DavidMWells@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Vivamus sit amet dolor arcu. Praesent fermentum semper justo, nec scelerisq…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1087"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1087" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1087" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Jennifer Selzer</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">JenniferLSelzer@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Maecenas sollicitudin felis et justo elementum, et lobortis justo vulputate…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1086"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1086" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1086" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Philip Norton</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">PhilipTNorton@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Etiam cursus orci tellus, ut vehicula odio mattis sit amet. Curabitur eros …
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1085"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1085" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1085" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Kevin Gregory</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">KevinJGregory@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Cras vel orci congue, tincidunt eros vitae, consectetur risus. Proin enim m…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1084"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1084" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1084" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">John Heiden</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">JohnCHeiden@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Fusce consequat dui ut orci tempus cursus. Vivamus ut neque id ipsum tempor…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1083"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1083" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1083" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Laura Shuler</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">LauraDShuler@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										In ac finibus erat. Curabitur sit amet ante nec tellus commodo commodo non …
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1082"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1082" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1082" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Walter Sullivan</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">WalterPSullivan@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Phasellus semper magna leo, ut porta nibh pretium sed. Interdum et malesuad…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1081"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1081" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1081" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Gary Austin</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">GaryJAustin@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec sit amet ero…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1080"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1080" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1080" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Mark Frahm</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">MarkTFrahm@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Proin euismod tellus quis tortor bibendum, a pulvinar libero fringilla. Cur…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
								<tr>
									<th scope="row" class="check-column"><input type="checkbox" name="entry_id[]" value="1079"></th>
									<td class="indicators column-indicators has-row-actions column-primary" data-colname="">
										<a href="#" class="indicator-star star" data-id="1079" title="Star entry"><span class="dashicons dashicons-star-filled"></span></a>
										<a href="#" class="indicator-read read" data-id="1079" title="Mark entry read"><span class="dashicons dashicons-marker"></span></a>
										<button type="button" class="toggle-row"><span class="screen-reader-text">Show more details</span></button>
									</td>
									<td class="wpforms_field_0 column-wpforms_field_0" data-colname="Name">Linda Reynolds</td>
									<td class="wpforms_field_1 column-wpforms_field_1" data-colname="Email">LindaJReynolds@example.com</td>
									<td class="wpforms_field_2 column-wpforms_field_2" data-colname="Comment or Message">
										Cras sodales sagittis maximus. Nunc vestibulum orci quis orci pulvinar vulp…
									</td>
									<td class="date column-date" data-colname="Date">July 27, 2017</td>
									<td class="actions column-actions" data-colname="Actions">
										<a href="#" title="View Form Entry" class="view">View</a> <span	class="sep">|</span> <a href="#" title="Delete Form Entry" class="delete">Delete</a>
									</td>
								</tr>
							</tbody>
							<tfoot>
								<tr>
									<td class="manage-column column-cb check-column">
										<label class="screen-reader-text" for="cb-select-all-2">Select All</label>
										<input id="cb-select-all-2" type="checkbox">
									</td>
									<th scope="col" class="manage-column column-indicators column-primary"></th>
									<th scope="col" class="manage-column column-wpforms_field_0">Name</th>
									<th scope="col" class="manage-column column-wpforms_field_1">Email</th>
									<th scope="col" class="manage-column column-wpforms_field_2">Comment or Message</th>
									<th scope="col" class="manage-column column-date sortable desc">
										<a href="#"><span>Date</span><span class="sorting-indicator"></span></a>
									</th>
									<th scope="col" class="manage-column column-actions">Actions</th>
								</tr>
							</tfoot>
						</table>
					</form>
				</div>
			</div>
		</div>
		<div class="clear"></div>

		<?php
	}

	/**
	 * Add appropriate styling to addons page.
	 *
	 * @since 1.0.4
	 * @deprecated 1.6.7
	 */
	public function addon_page_enqueues() {

		_deprecated_function( __METHOD__, '1.6.7 of the WPForms plugin', "wpforms()->get( 'addons_page' )->enqueues()" );

		wpforms()->get( 'addons_page' )->enqueues();
	}

	/**
	 * Addons page.
	 *
	 * @since 1.0.0
	 * @deprecated 1.6.7
	 */
	public function addons_page() {

		_deprecated_function( __METHOD__, '1.6.7 of the WPForms plugin', "wpforms()->get( 'addons_page' )->output()" );

		if ( ! wpforms_is_admin_page( 'addons' ) ) {
			return;
		}

		wpforms()->get( 'addons_page' )->output();
	}

	/**
	 * Increase entries count once a form is submitted.
	 *
	 * @since 1.5.9
	 *
	 * @param array      $fields  Set of form fields.
	 * @param array      $entry   Entry contents.
	 * @param int|string $form_id Form ID.
	 */
	public function update_entry_count( $fields, $entry, $form_id ) {

		global $wpdb;

		if ( ! apply_filters( 'wpforms_dash_widget_allow_entries_count_lite', true ) ) {
			return;
		}

		$form_id = absint( $form_id );

		if ( empty( $form_id ) ) {
			return;
		}

		if ( add_post_meta( $form_id, 'wpforms_entries_count', 1, true ) ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->postmeta}
					SET meta_value = meta_value + 1
					WHERE post_id = %d AND meta_key = 'wpforms_entries_count'",
				$form_id
			)
		);
	}

	/**
	 * Submit entry to the Lite Connect API.
	 *
	 * @since 1.7.4
	 *
	 * @param array $fields    Set of form fields.
	 * @param array $entry     Entry contents.
	 * @param int   $form_id   Form ID.
	 * @param array $form_data Form data.
	 */
	public function entry_submit( $fields, $entry, $form_id, $form_data = [] ) {

		$submission = wpforms()->get( 'submission' );

		$submission->register( $fields, $entry, $form_id, $form_data );

		// Prepare the entry args.
		$entry_args = $submission->prepare_entry_data();

		// Submit entry args and form data to the Lite Connect API.
		if (
			 LiteConnect::is_allowed() &&
			 LiteConnect::is_enabled() &&
			 ! empty( $entry_args )
		) {
			( new LiteConnectIntegration() )->submit( $entry_args, $form_data );
		}
	}

	/**
	 * Add Lite-specific templates to the list of searchable template paths.
	 *
	 * @since 1.6.6
	 *
	 * @param array $paths Paths to templates.
	 *
	 * @return array
	 */
	public function add_templates( $paths ) {

		$paths = (array) $paths;

		$paths[102] = trailingslashit( __DIR__ . '/templates' );

		return $paths;
	}

	/**
	 * Render Upgrade to Pro admin bar menu item.
	 *
	 * @since 1.7.4
	 *
	 * @param WP_Admin_Bar $wp_admin_bar WordPress Admin Bar object.
	 */
	public function upgrade_to_pro_menu( WP_Admin_Bar $wp_admin_bar ) {

		$current_screen      = is_admin() ? get_current_screen() : null;
		$upgrade_utm_content = $current_screen === null ? 'Upgrade to Pro' : 'Upgrade to Pro - ' . $current_screen->base;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$upgrade_utm_content = empty( $_GET['view'] ) ? $upgrade_utm_content : $upgrade_utm_content . ': ' . sanitize_key( $_GET['view'] );

		$wp_admin_bar->add_menu(
			[
				'parent' => 'wpforms-menu',
				'id'     => 'wpforms-upgrade',
				'title'  => esc_html__( 'Upgrade to Pro', 'wpforms-lite' ),
				'href'   => esc_url(
					add_query_arg(
						[
							'utm_campaign' => 'liteplugin',
							'utm_medium'   => 'admin-bar',
							'utm_source'   => 'WordPress',
							'utm_content'  => $upgrade_utm_content,
							'utm_locale'   => wpforms_sanitize_key( get_locale() ),
						],
						'https://wpforms.com/lite-upgrade/'
					)
				),
				'meta'   => [
					'target' => '_blank',
					'rel'    => 'noopener noreferrer',
				],
			]
		);
	}

	/**
	 * Handle plugin installation upon activation.
	 *
	 * @since 1.7.4
	 */
	public function install() {

		// Restart the import flags for Lite Connect if needed.
		if ( class_exists( LiteConnectIntegration::class ) ) {
			LiteConnectIntegration::maybe_restart_import_flag();
		}
	}
}

new WPForms_Lite();
