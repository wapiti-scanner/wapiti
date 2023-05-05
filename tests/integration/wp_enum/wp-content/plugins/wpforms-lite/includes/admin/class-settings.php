<?php

/**
 * Settings class.
 *
 * @since 1.0.0
 */
class WPForms_Settings {

	/**
	 * The current active tab.
	 *
	 * @since 1.3.9
	 *
	 * @var string
	 */
	public $view;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		// Maybe load settings page.
		add_action( 'admin_init', [ $this, 'init' ] );
	}

	/**
	 * Determine if the user is viewing the settings page, if so, party on.
	 *
	 * @since 1.0.0
	 */
	public function init() {

		// Only load if we are actually on the settings page.
		if ( ! wpforms_is_admin_page( 'settings' ) ) {
			return;
		}

		// Include API callbacks and functions.
		require_once WPFORMS_PLUGIN_DIR . 'includes/admin/settings-api.php';

		// Watch for triggered save.
		$this->save_settings();

		// Determine the current active settings tab.
		$this->view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : 'general'; // phpcs:ignore WordPress.CSRF.NonceVerification

		add_action( 'admin_enqueue_scripts', [ $this, 'enqueues' ] );
		add_action( 'wpforms_admin_page', [ $this, 'output' ] );

		// Monitor custom tables.
		$this->monitor_custom_tables();

		// Hook for addons.
		do_action( 'wpforms_settings_init', $this );
	}

	/**
	 * Sanitize and save settings.
	 *
	 * @since 1.3.9
	 */
	public function save_settings() {

		// Check nonce and other various security checks.
		if ( ! isset( $_POST['wpforms-settings-submit'] ) || empty( $_POST['nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'wpforms-settings-nonce' ) ) {
			return;
		}

		if ( ! wpforms_current_user_can() ) {
			return;
		}

		if ( empty( $_POST['view'] ) ) {
			return;
		}

		$current_view = sanitize_key( $_POST['view'] );

		// Get registered fields and current settings.
		$fields   = $this->get_registered_settings( $current_view );
		$settings = get_option( 'wpforms_settings', [] );

		// Views excluded from saving list.
		$exclude_views = apply_filters( 'wpforms_settings_exclude_view', [], $fields, $settings );

		if ( is_array( $exclude_views ) && in_array( $current_view, $exclude_views, true ) ) {
			// Run a custom save processing for excluded views.
			do_action( 'wpforms_settings_custom_process', $current_view, $fields, $settings );

			return;
		}

		if ( empty( $fields ) || ! is_array( $fields ) ) {
			return;
		}

		// Sanitize and prep each field.
		foreach ( $fields as $id => $field ) {

			// Certain field types are not valid for saving and are skipped.
			$exclude = apply_filters( 'wpforms_settings_exclude_type', [ 'content', 'license', 'providers' ] );

			if ( empty( $field['type'] ) || in_array( $field['type'], $exclude, true ) ) {
				continue;
			}

			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$value      = isset( $_POST[ $id ] ) ? trim( wp_unslash( $_POST[ $id ] ) ) : false;
			$value_prev = isset( $settings[ $id ] ) ? $settings[ $id ] : false;

			// Custom filter can be provided for sanitizing, otherwise use defaults.
			if ( ! empty( $field['filter'] ) && is_callable( $field['filter'] ) ) {

				$value = call_user_func( $field['filter'], $value, $id, $field, $value_prev );

			} else {

				switch ( $field['type'] ) {
					case 'checkbox':
					case 'toggle':
						$value = (bool) $value;
						break;

					case 'image':
						$value = esc_url_raw( $value );
						break;

					case 'color':
						$value = wpforms_sanitize_hex_color( $value );
						break;

					case 'number':
						$value = (float) $value;
						break;

					case 'radio':
					case 'select':
						$value = $this->validate_field_with_options( $field, $value, $value_prev );
						break;

					case 'text':
					default:
						$value = sanitize_text_field( $value );
						break;
				}
			}

			// Add to settings.
			$settings[ $id ] = $value;
		}

		// Save settings.
		wpforms_update_settings( $settings );

		\WPForms\Admin\Notice::success( esc_html__( 'Settings were successfully saved.', 'wpforms-lite' ) );
	}

	/**
	 * Enqueue assets for the settings page.
	 *
	 * @since 1.0.0
	 */
	public function enqueues() {

		do_action( 'wpforms_settings_enqueue' );
	}

	/**
	 * Return registered settings tabs.
	 *
	 * @since 1.3.9
	 *
	 * @return array
	 */
	public function get_tabs() {

		$tabs = [
			'general'      => [
				'name'   => esc_html__( 'General', 'wpforms-lite' ),
				'form'   => true,
				'submit' => esc_html__( 'Save Settings', 'wpforms-lite' ),
			],
			'email'        => [
				'name'   => esc_html__( 'Email', 'wpforms-lite' ),
				'form'   => true,
				'submit' => esc_html__( 'Save Settings', 'wpforms-lite' ),
			],
			'validation'   => [
				'name'   => esc_html__( 'Validation', 'wpforms-lite' ),
				'form'   => true,
				'submit' => esc_html__( 'Save Settings', 'wpforms-lite' ),
			],
			'integrations' => [
				'name'   => esc_html__( 'Integrations', 'wpforms-lite' ),
				'form'   => false,
				'submit' => false,
			],
			'geolocation'  => [
				'name'   => esc_html__( 'Geolocation', 'wpforms-lite' ),
				'form'   => false,
				'submit' => false,
			],
			'misc'         => [
				'name'   => esc_html__( 'Misc', 'wpforms-lite' ),
				'form'   => true,
				'submit' => esc_html__( 'Save Settings', 'wpforms-lite' ),
			],
		];

		return apply_filters( 'wpforms_settings_tabs', $tabs );
	}

	/**
	 * Output tab navigation area.
	 *
	 * @since 1.3.9
	 */
	public function tabs() {

		$tabs = $this->get_tabs();

		echo '<ul class="wpforms-admin-tabs">';
		foreach ( $tabs as $id => $tab ) {

			$active = $id === $this->view ? 'active' : '';
			$link   = add_query_arg( 'view', $id, admin_url( 'admin.php?page=wpforms-settings' ) );

			echo '<li><a href="' . esc_url_raw( $link ) . '" class="' . esc_attr( $active ) . '">' . esc_html( $tab['name'] ) . '</a></li>';
		}
		echo '</ul>';
	}

	/**
	 * Return all the default registered settings fields.
	 *
	 * @since 1.3.9
	 *
	 * @param string $view The current view (tab) on Settings page.
	 *
	 * @return array
	 */
	public function get_registered_settings( $view = '' ) {

		$defaults = [
			// General Settings tab.
			'general'      => [
				'license-heading' => [
					'id'       => 'license-heading',
					'content'  => '<h4>' . esc_html__( 'License', 'wpforms-lite' ) . '</h4><p>' . esc_html__( 'Your license key provides access to updates and addons.', 'wpforms-lite' ) . '</p>',
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading' ],
				],
				'license-key'     => [
					'id'   => 'license-key',
					'name' => esc_html__( 'License Key', 'wpforms-lite' ),
					'type' => 'license',
				],
				'general-heading' => [
					'id'       => 'general-heading',
					'content'  => '<h4>' . esc_html__( 'General', 'wpforms-lite' ) . '</h4>',
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading', 'no-desc' ],
				],
				'disable-css'     => [
					'id'        => 'disable-css',
					'name'      => esc_html__( 'Include Form Styling', 'wpforms-lite' ),
					'desc'      => sprintf(
						wp_kses( /* translators: %s - WPForms.com form styling setting URL. */
							__( 'Determines which CSS files to load and use for the site (<a href="%s" target="_blank" rel="noopener noreferrer">please see our tutorial for full details</a>). "Base and Form Theme Styling" is recommended, unless you are experienced with CSS or instructed by support to change settings.', 'wpforms-lite' ),
							[
								'a' => [
									'href'   => [],
									'target' => [],
									'rel'    => [],
								],
							]
						),
						esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-choose-an-include-form-styling-setting/', 'settings-license', 'Form Styling Documentation' ) )
					),
					'type'      => 'select',
					'choicesjs' => true,
					'default'   => 1,
					'options'   => [
						1 => esc_html__( 'Base and form theme styling', 'wpforms-lite' ),
						2 => esc_html__( 'Base styling only', 'wpforms-lite' ),
						3 => esc_html__( 'No styling', 'wpforms-lite' ),
					],
				],
				'global-assets'   => [
					'id'   => 'global-assets',
					'name' => esc_html__( 'Load Assets Globally', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to load WPForms assets site-wide. Only check if your site is having compatibility issues or instructed to by support.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
				'gdpr-heading'    => [
					'id'       => 'GDPR',
					'content'  => '<h4>' . esc_html__( 'GDPR', 'wpforms-lite' ) . '</h4>',
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading', 'no-desc' ],
				],
				'gdpr'            => [
					'id'   => 'gdpr',
					'name' => esc_html__( 'GDPR Enhancements', 'wpforms-lite' ),
					'desc' => sprintf(
						wp_kses( /* translators: %s - WPForms.com GDPR documentation URL. */
							__( 'Check this option to enable GDPR related features and enhancements. <a href="%s" target="_blank" rel="noopener noreferrer">Read our GDPR documentation</a> to learn more.', 'wpforms-lite' ),
							[
								'a' => [
									'href'   => [],
									'target' => [],
									'rel'    => [],
								],
							]
						),
						esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-create-gdpr-compliant-forms/', 'settings-license', 'GDPR Documentation' ) )
					),
					'type' => 'checkbox',
				],
			],
			// Email settings tab.
			'email'        => [
				'email-heading'          => [
					'id'       => 'email-heading',
					'content'  => '<h4>' . esc_html__( 'Email', 'wpforms-lite' ) . '</h4>' . wpforms()->get( 'education_smtp_notice' )->get_template(),
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading', 'no-desc' ],
				],
				'email-async'            => [
					'id'   => 'email-async',
					'name' => esc_html__( 'Optimize Email Sending', 'wpforms-lite' ),
					'desc' => sprintf(
						wp_kses( /* translators: %s - WPForms.com Email settings documentation URL. */
							__( 'Check this option to enable sending emails asynchronously, which can make submission processing faster but may delay email delivery by a minute or two. Learn more <a href="%s" target="_blank" rel="noopener noreferrer">in our documentation</a>.', 'wpforms-lite' ),
							[
								'a' => [
									'href'   => [],
									'target' => [],
									'rel'    => [],
								],
							]
						),
						esc_url( wpforms_utm_link( 'https://wpforms.com/docs/a-complete-guide-to-wpforms-settings/#email', 'Settings - Email', 'Optimize Email Sending Documentation' ) )
					),
					'type' => 'checkbox',
				],
				'email-template'         => [
					'id'      => 'email-template',
					'name'    => esc_html__( 'Template', 'wpforms-lite' ),
					'desc'    => esc_html__( 'Determines how email notifications will be formatted. HTML Templates are the default.', 'wpforms-lite' ),
					'type'    => 'radio',
					'default' => 'default',
					'options' => [
						'default' => esc_html__( 'HTML Template', 'wpforms-lite' ),
						'none'    => esc_html__( 'Plain text', 'wpforms-lite' ),
					],
				],
				'email-header-image'     => [
					'id'   => 'email-header-image',
					'name' => esc_html__( 'Header Image', 'wpforms-lite' ),
					'desc' => wp_kses( __( 'Upload or choose a logo to be displayed at the top of email notifications.<br>Recommended size is 300x100 or smaller for best support on all devices.', 'wpforms-lite' ), [ 'br' => [] ] ),
					'type' => 'image',
				],
				'email-background-color' => [
					'id'      => 'email-background-color',
					'name'    => esc_html__( 'Background Color', 'wpforms-lite' ),
					'desc'    => esc_html__( 'Customize the background color of the HTML email template.', 'wpforms-lite' ),
					'type'    => 'color',
					'default' => '#e9eaec',
					'data'    => [
						'fallback-color' => wpforms_setting( 'email-background-color', '#e9eaec' ),
					],
				],
				'email-carbon-copy'      => [
					'id'   => 'email-carbon-copy',
					'name' => esc_html__( 'Carbon Copy', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to enable the ability to CC: email addresses in the form notification settings.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
			],
			// Validation messages settings tab.
			'validation'   => [
				'validation-heading'               => [
					'id'       => 'validation-heading',
					'content'  => sprintf( /* translators: %s - WPForms.com smart tags documentation URL. */
						esc_html__( '%1$s These messages are displayed to the users as they fill out a form in real-time. Messages can include plain text and/or %2$sSmart Tags%3$s.', 'wpforms-lite' ),
						'<h4>' . esc_html__( 'Validation Messages', 'wpforms-lite' )
						. '</h4><p>',
						'<a href="' . esc_url( wpforms_utm_link( 'https://wpforms.com/docs/how-to-use-smart-tags-in-wpforms/#smart-tags', 'Settings - Validation', 'Smart Tag Documentation' ) ) . '" target="_blank" rel="noopener noreferrer">',
						'</a>'
					),
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading' ],
				],
				'validation-required'              => [
					'id'      => 'validation-required',
					'name'    => esc_html__( 'Required', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'This field is required.', 'wpforms-lite' ),
				],
				'validation-email'                 => [
					'id'      => 'validation-email',
					'name'    => esc_html__( 'Email', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'Please enter a valid email address.', 'wpforms-lite' ),
				],
				'validation-email-suggestion'      => [
					'id'      => 'validation-email-suggestion',
					'name'    => esc_html__( 'Email Suggestion', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => sprintf( /* translators: %s - suggested email address. */
						esc_html__( 'Did you mean %s?', 'wpforms-lite' ),
						'{suggestion}'
					),
				],
				'validation-email-restricted'      => [
					'id'      => 'validation-email-restricted',
					'name'    => esc_html__( 'Email Restricted', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'This email address is not allowed.', 'wpforms-lite' ),
				],
				'validation-number'                => [
					'id'      => 'validation-number',
					'name'    => esc_html__( 'Number', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'Please enter a valid number.', 'wpforms-lite' ),
				],
				'validation-number-positive'       => [
					'id'      => 'validation-number-positive',
					'name'    => esc_html__( 'Number Positive', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'Please enter a valid positive number.', 'wpforms-lite' ),
				],
				'validation-confirm'               => [
					'id'      => 'validation-confirm',
					'name'    => esc_html__( 'Confirm Value', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'Field values do not match.', 'wpforms-lite' ),
				],
				'validation-inputmask-incomplete'  => [
					'id'      => 'validation-inputmask-incomplete',
					'name'    => esc_html__( 'Input Mask Incomplete', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'Please fill out the field in required format.', 'wpforms-lite' ),
				],
				'validation-check-limit'           => [
					'id'      => 'validation-check-limit',
					'name'    => esc_html__( 'Checkbox Selection Limit', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => esc_html__( 'You have exceeded the number of allowed selections: {#}.', 'wpforms-lite' ),
				],
				'validation-character-limit'       => [
					'id'      => 'validation-character-limit',
					'name'    => esc_html__( 'Character Limit', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => sprintf( /* translators: %1$s - characters limit, %2$s - number of characters left. */
						esc_html__( 'Limit is %1$s characters. Characters remaining: %2$s.', 'wpforms-lite' ),
						'{limit}',
						'{remaining}'
					),
				],
				'validation-word-limit'            => [
					'id'      => 'validation-word-limit',
					'name'    => esc_html__( 'Word Limit', 'wpforms-lite' ),
					'type'    => 'text',
					'default' => sprintf( /* translators: %1$s - words limit, %2$s - number of words left. */
						esc_html__( 'Limit is %1$s words. Words remaining: %2$s.', 'wpforms-lite' ),
						'{limit}',
						'{remaining}'
					),
				],
			],
			// Provider integrations settings tab.
			'integrations' => [
				'integrations-heading'   => [
					'id'       => 'integrations-heading',
					'content'  => '<h4>' . esc_html__( 'Integrations', 'wpforms-lite' ) . '</h4><p>' . esc_html__( 'Manage integrations with popular providers such as Constant Contact, Mailchimp, Zapier, and more.', 'wpforms-lite' ) . '</p>',
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading' ],
				],
				'integrations-providers' => [
					'id'      => 'integrations-providers',
					'content' => '<h4>' . esc_html__( 'Integrations', 'wpforms-lite' ) . '</h4><p>' . esc_html__( 'Manage integrations with popular providers such as Constant Contact, Mailchimp, Zapier, and more.', 'wpforms-lite' ) . '</p>',
					'type'    => 'providers',
					'wrap'    => 'none',
				],
			],
			// Misc. settings tab.
			'misc'         => [
				'misc-heading'       => [
					'id'       => 'misc-heading',
					'content'  => '<h4>' . esc_html__( 'Misc', 'wpforms-lite' ) . '</h4>',
					'type'     => 'content',
					'no_label' => true,
					'class'    => [ 'section-heading', 'no-desc' ],
				],
				'hide-announcements' => [
					'id'   => 'hide-announcements',
					'name' => esc_html__( 'Hide Announcements', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to hide plugin announcements and update details.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
				'hide-admin-bar'     => [
					'id'   => 'hide-admin-bar',
					'name' => esc_html__( 'Hide Admin Bar Menu', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to hide the WPForms admin bar menu.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
				'uninstall-data'     => [
					'id'   => 'uninstall-data',
					'name' => esc_html__( 'Uninstall WPForms', 'wpforms-lite' ),
					'desc' => esc_html__( 'Check this option to remove ALL WPForms data upon plugin deletion. All forms and settings will be unrecoverable.', 'wpforms-lite' ),
					'type' => 'checkbox',
				],
			],
		];

		// TODO: move this to Pro.
		if ( wpforms()->is_pro() ) {
			$defaults['misc']['uninstall-data']['desc'] = esc_html__( 'Check this option to remove ALL WPForms data upon plugin deletion. All forms, entries, and uploaded files will be unrecoverable.', 'wpforms-lite' );
		}

		$defaults = apply_filters( 'wpforms_settings_defaults', $defaults );

		// Take care of invalid views.
		if ( ! empty( $view ) && ! array_key_exists( $view, $defaults ) ) {
			$this->view = key( $defaults );

			return reset( $defaults );
		}

		return empty( $view ) ? $defaults : $defaults[ $view ];
	}

	/**
	 * Return array containing markup for all the appropriate settings fields.
	 *
	 * @since 1.3.9
	 *
	 * @param string $view View slug.
	 *
	 * @return array
	 */
	public function get_settings_fields( $view = '' ) {

		$fields   = [];
		$settings = $this->get_registered_settings( $view );

		foreach ( $settings as $id => $args ) {

			$fields[ $id ] = wpforms_settings_output_field( $args );
		}

		return apply_filters( 'wpforms_settings_fields', $fields, $view );
	}

	/**
	 * Build the output for the plugin settings page.
	 *
	 * @since 1.0.0
	 */
	public function output() {

		$tabs   = $this->get_tabs();
		$fields = $this->get_settings_fields( $this->view );
		?>

		<div id="wpforms-settings" class="wrap wpforms-admin-wrap">

			<?php $this->tabs(); ?>

			<h1 class="wpforms-h1-placeholder"></h1>

			<?php
			if ( wpforms()->is_pro() && class_exists( 'WPForms_License', false ) ) {
				wpforms()->get( 'license' )->notices( true );
			}
			?>

			<div class="wpforms-admin-content wpforms-admin-settings wpforms-admin-content-<?php echo esc_attr( $this->view ); ?> wpforms-admin-settings-<?php echo esc_attr( $this->view ); ?>">

				<?php
				// Some tabs rely on AJAX and do not contain a form, such as Integrations.
				if ( ! empty( $tabs[ $this->view ]['form'] ) ) :
				?>
				<form class="wpforms-admin-settings-form" method="post">
					<input type="hidden" name="action" value="update-settings">
					<input type="hidden" name="view" value="<?php echo esc_attr( $this->view ); ?>">
					<input type="hidden" name="nonce" value="<?php echo esc_attr( wp_create_nonce( 'wpforms-settings-nonce' ) ); ?>">
					<?php endif; ?>

					<?php do_action( 'wpforms_admin_settings_before', $this->view, $fields ); ?>

					<?php
					foreach ( $fields as $field ) {
						echo $field; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					}
					?>

					<?php if ( ! empty( $tabs[ $this->view ]['submit'] ) ) : ?>
						<p class="submit">
							<button type="submit" class="wpforms-btn wpforms-btn-md wpforms-btn-orange" name="wpforms-settings-submit">
								<?php
								// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
								echo $tabs[ $this->view ]['submit'];
								?>
							</button>
						</p>
					<?php endif; ?>

					<?php do_action( 'wpforms_admin_settings_after', $this->view, $fields ); ?>

					<?php if ( ! empty( $tabs[ $this->view ]['form'] ) ) : ?>
				</form>
			<?php endif; ?>

			</div>

		</div>

		<?php
	}

	/**
	 * Monitor that all custom tables exist and recreate if missing.
	 * This logic works on Settings > General page only.
	 *
	 * @since 1.6.2
	 */
	public function monitor_custom_tables() {

		// Proceed on Settings plugin admin area page only.
		if ( $this->view !== 'general' ) {
			return;
		}

		/*
		 * Tasks Meta table.
		 */
		$meta = new \WPForms\Tasks\Meta();

		if ( $meta->table_exists() ) {
			return;
		}

		$meta->create_table();
	}

	/**
	 * Validate radio and select fields.
	 *
	 * @since 1.7.5.5
	 *
	 * @param array $field      Field.
	 * @param mixed $value      Value.
	 * @param mixed $value_prev Previous value.
	 *
	 * @return mixed
	 */
	private function validate_field_with_options( $field, $value, $value_prev ) {

		$value = sanitize_text_field( $value );

		if ( isset( $field['options'] ) && array_key_exists( $value, $field['options'] ) ) {
			return $value;
		}

		return isset( $field['default'] ) ? $field['default'] : $value_prev;
	}
}

new WPForms_Settings();
