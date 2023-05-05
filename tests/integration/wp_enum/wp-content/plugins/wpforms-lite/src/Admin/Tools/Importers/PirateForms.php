<?php

namespace WPForms\Admin\Tools\Importers;

use WPForms\Helpers\PluginSilentUpgrader;
use WPForms\Helpers\PluginSilentUpgraderSkin;

/**
 * Pirate Forms Importer class.
 *
 * @since 1.6.6
 */
class PirateForms extends Base {

	/**
	 * Direct URL to download the latest version of WP Mail SMTP plugin from WP.org repo.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	const URL_SMTP_ZIP = 'https://downloads.wordpress.org/plugin/wp-mail-smtp.zip';

	/**
	 * WP Mail SMTP plugin basename.
	 *
	 * @since 1.6.6
	 *
	 * @var string
	 */
	const SLUG_SMTP_PLUGIN = 'wp-mail-smtp/wp_mail_smtp.php';

	/**
	 * Default PirateForms smart tags.
	 *
	 * @since 1.6.6
	 *
	 * @var array
	 */
	public static $tags = [
		'[email]',
	];

	/**
	 * Define required properties.
	 *
	 * @since 1.6.6
	 */
	public function init() {

		$this->name = 'Pirate Forms';
		$this->slug = 'pirate-forms';
		$this->path = 'pirate-forms/pirate-forms.php';
	}

	/**
	 * Get ALL THE FORMS.
	 * We need only ID's and names here.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	public function get_forms() {

		// Union those arrays, as array_merge() does keys reindexing.
		$forms = $this->get_default_forms() + $this->get_pro_forms();

		// Sort by IDs ASC.
		ksort( $forms );

		return $forms;
	}

	/**
	 * Pirate Forms has a default form, which doesn't have an ID.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	protected function get_default_forms() {

		$form = \PirateForms_Util::get_form_options();

		// Just make sure that it's there and not broken.
		if ( empty( $form ) ) {
			return [];
		}

		return [ 0 => esc_html__( 'Default Form', 'wpforms-lite' ) ];
	}

	/**
	 * Copy-paste from Pro plugin code, it doesn't have API to get this data easily.
	 *
	 * @since 1.6.6
	 *
	 * @return array
	 */
	protected function get_pro_forms() {

		$forms = [];
		$query = new \WP_Query(
			[
				'post_type'              => 'pf_form',
				'post_status'            => 'publish',
				'posts_per_page'         => - 1,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
			]
		);

		if ( $query->have_posts() ) {
			while ( $query->have_posts() ) {
				$query->the_post();
				$forms[ get_the_ID() ] = get_the_title();
			}
		}

		return $forms;
	}

	/**
	 * Get a single form options.
	 *
	 * @since 1.6.6
	 *
	 * @param int $id Form ID.
	 *
	 * @return array
	 */
	public function get_form( $id ) {

		return \PirateForms_Util::get_form_options( (int) $id );
	}

	/**
	 * Import a single form using AJAX.
	 *
	 * @since 1.6.6
	 */
	public function import_form() {

		// Run a security check.
		check_ajax_referer( 'wpforms-admin', 'nonce' );

		// Check for permissions.
		if ( ! wpforms_current_user_can( 'create_forms' ) ) {
			wp_send_json_error();
		}

		$analyze           = isset( $_POST['analyze'] );
		$pf_form_id        = isset( $_POST['form_id'] ) ? (int) $_POST['form_id'] : 0;
		$pf_form           = $this->get_form( $pf_form_id );
		$pf_fields_custom  = \PirateForms_Util::get_post_meta( $pf_form_id, 'custom' );
		$pf_fields_default = [
			'name',
			'email',
			'subject',
			'message',
			'attachment',
			'checkbox',
			'recaptcha',
		];
		$fields_pro_plain  = [ 'tel' ]; // Convert them in Lite to the closest Standard alternatives.
		$fields_pro_omit   = [ 'label', 'file', 'attachment' ]; // Strict PRO fields with no Lite alternatives.
		$upgrade_plain     = [];
		$upgrade_omit      = [];
		$unsupported       = [];
		$fields            = [];

		if ( ! empty( $pf_fields_custom[0] ) ) {
			$pf_fields_custom = $pf_fields_custom[0];
		} else {
			$pf_fields_custom = [];
		}

		if ( empty( $pf_form_id ) ) {
			$pf_form_name = esc_html__( 'Default Form', 'wpforms-lite' );
		} else {
			$pf_form_name = get_post_field( 'post_title', $pf_form_id );
		}
		$pf_form_name = wpforms_decode_string( apply_filters( 'the_title', $pf_form_name, $pf_form_id ) );

		// Prepare all DEFAULT fields.
		foreach ( $pf_fields_default as $field ) {
			// Ignore fields that are not displayed or not added at all.
			if ( empty( $pf_form[ 'pirateformsopt_' . $field . '_field' ] ) ) {
				continue;
			}

			// Ignore certain fields as they are dealt with later.
			if ( $field === 'recaptcha' ) {
				continue;
			}

			$required = $pf_form[ 'pirateformsopt_' . $field . '_field' ] === 'req' ? '1' : '';
			$label    = ! empty( $pf_form[ 'pirateformsopt_label_' . $field ] ) ? $pf_form[ 'pirateformsopt_label_' . $field ] : ucwords( $field );

			// If it is Lite and it's a field type not included, make a note then continue to the next field.
			if ( ! wpforms()->is_pro() && in_array( $field, $fields_pro_plain, true ) ) {
				$upgrade_plain[] = $label;
			}

			if ( ! wpforms()->is_pro() && in_array( $field, $fields_pro_omit, true ) ) {
				$upgrade_omit[] = $label;

				continue;
			}

			// Determine next field ID to assign.
			if ( empty( $fields ) ) {
				$field_id = 1;
			} else {
				$field_id = (int) max( array_keys( $fields ) ) + 1;
			}

			// Separately process certain fields.
			switch ( $field ) {
				case 'name':
				case 'email':
				case 'subject':
				case 'message':
					$type = $field;

					if ( $field === 'subject' ) {
						$type = 'text';
					} elseif ( $field === 'message' ) {
						$type = 'textarea';
					}

					$fields[ $field_id ] = [
						'id'       => $field_id,
						'type'     => $type,
						'label'    => $label,
						'required' => $required,
						'size'     => 'medium',
					];

					if ( $field === 'name' ) {
						$fields[ $field_id ]['format'] = 'simple';
					}
					break;

				case 'checkbox':
					$fields[ $field_id ] = [
						'id'         => $field_id,
						'type'       => 'checkbox',
						'label'      => esc_html__( 'Single Checkbox Field', 'wpforms-lite' ),
						'choices'    => [
							1 => [
								'label' => $label,
								'value' => '',
							],
						],
						'size'       => 'medium',
						'required'   => $required,
						'label_hide' => true,
					];
					break;

				case 'attachment':
				case 'file':
					$fields[ $field_id ] = [
						'id'         => $field_id,
						'type'       => 'file-upload',
						'label'      => $label,
						'required'   => $required,
						'label_hide' => true,
					];

					// If PF attachments were saved into FS, we need to save them in WP Media.
					// That will allow admins to easily delete if needed.
					if (
						! empty( $pf_form['pirateformsopt_save_attachment'] ) &&
						$pf_form['pirateformsopt_save_attachment'] === 'yes'
					) {
						$fields[ $field_id ]['media_library'] = true;
					}
					break;
			}
		}

		// Prepare all CUSTOM fields.
		foreach ( $pf_fields_custom as $id => $field ) {
			// Ignore fields that are not displayed.
			if ( empty( $field['display'] ) ) {
				continue;
			}

			$required = $field['display'] === 'req' ? '1' : ''; // Possible values in PF: 'yes', 'req'.
			$label    = sanitize_text_field( $field['label'] );

			// If it is Lite and it's a field type not included, make a note then continue to the next field.
			if ( ! wpforms()->is_pro() && in_array( $field['type'], $fields_pro_plain, true ) ) {
				$upgrade_plain[] = $label;
			}
			if ( ! wpforms()->is_pro() && in_array( $field['type'], $fields_pro_omit, true ) ) {
				$upgrade_omit[] = $label;

				continue;
			}

			// Determine next field ID to assign.
			if ( empty( $fields ) ) {
				$field_id = 1;
			} else {
				$field_id = (int) max( array_keys( $fields ) ) + 1;
			}

			switch ( $field['type'] ) {
				case 'text':
				case 'textarea':
				case 'number':
				case 'tel':
					$type = $field['type'];

					if ( $field['type'] === 'textarea' ) {
						$type = 'textarea';
					}
					if ( $field['type'] === 'tel' ) {
						$type = 'phone';
					}

					$fields[ $field_id ] = [
						'id'       => $field_id,
						'type'     => $type,
						'label'    => $label,
						'required' => $required,
						'size'     => 'medium',
					];

					if ( $field['type'] === 'tel' ) {
						$fields[ $field_id ]['format'] = 'international';
					}
					break;

				case 'checkbox':
					$fields[ $field_id ] = [
						'id'         => $field_id,
						'type'       => 'checkbox',
						'label'      => esc_html__( 'Single Checkbox Field', 'wpforms-lite' ),
						'choices'    => [
							1 => [
								'label' => $label,
								'value' => '',
							],
						],
						'size'       => 'medium',
						'required'   => $required,
						'label_hide' => true,
					];
					break;

				case 'select':
				case 'multiselect':
					$options = [];
					$i       = 1;
					$type    = 'select';

					if ( $field['type'] === 'multiselect' ) {
						$type = 'checkbox';
					}

					foreach ( explode( PHP_EOL, $field['options'] ) as $option ) {
						$options[ $i ] = [
							'label' => $option,
							'value' => '',
							'image' => '',
						];

						$i ++;
					}

					$fields[ $field_id ] = [
						'id'       => $field_id,
						'type'     => $type,
						'label'    => $label,
						'required' => $required,
						'size'     => 'medium',
						'choices'  => $options,
					];
					break;

				case 'label':
					$fields[ $field_id ] = [
						'id'            => $field_id,
						'type'          => 'html',
						'code'          => $field['label'],
						'label_disable' => true,
					];
					break;

				case 'file':
					$fields[ $field_id ] = [
						'id'         => $field_id,
						'type'       => 'file-upload',
						'label'      => $label,
						'required'   => $required,
						'label_hide' => true,
					];

					// If PF attachments were saved into FS, we need to save them in WP Media.
					// That will allow admins to easily delete if needed.
					if (
						! empty( $pf_form['pirateformsopt_save_attachment'] ) &&
						$pf_form['pirateformsopt_save_attachment'] === 'yes'
					) {
						$fields[ $field_id ]['media_library'] = true;
					}
					break;
			}
		}

		// If we are analyzing the form (in Lite only),
		// we can stop here and return the details about this form.
		if ( $analyze ) {
			wp_send_json_success(
				[
					'name'          => $pf_form_name,
					'upgrade_plain' => $upgrade_plain,
					'upgrade_omit'  => $upgrade_omit,
				]
			);
		}

		// Make sure we have imported some fields.
		if ( empty( $fields ) ) {
			wp_send_json_success(
				[
					'error' => true,
					'name'  => $pf_form_name,
					'msg'   => esc_html__( 'No form fields found.', 'wpforms-lite' ),
				]
			);
		}

		// Create a form array, that holds all the data.
		$form = [
			'id'       => '',
			'field_id' => '',
			'fields'   => $fields,
			'settings' => [
				'form_title'             => $pf_form_name,
				'form_desc'              => '',
				'submit_text'            => stripslashes( $pf_form['pirateformsopt_label_submit_btn'] ),
				'submit_text_processing' => esc_html__( 'Sending', 'wpforms-lite' ),
				'notification_enable'    => '1',
				'notifications'          => [
					1 => [
						'notification_name' => esc_html__( 'Default Notification', 'wpforms-lite' ),
						'email'             => $pf_form['pirateformsopt_email_recipients'],
						/* translators: %s - form name. */
						'subject'           => sprintf( esc_html__( 'New Entry: %s', 'wpforms-lite' ), $pf_form_name ),
						'sender_name'       => get_bloginfo( 'name' ),
						'sender_address'    => $this->get_smarttags( $pf_form['pirateformsopt_email'], $fields ),
						'replyto'           => '',
						'message'           => '{all_fields}',
					],
				],
				'confirmations'          => [
					1 => [
						'type'           => empty( $pf_form['pirateformsopt_thank_you_url'] ) ? 'message' : 'page',
						'page'           => (int) $pf_form['pirateformsopt_thank_you_url'],
						'message'        => ! empty( $pf_form['pirateformsopt_label_submit'] ) ? $pf_form['pirateformsopt_label_submit'] : esc_html__( 'Thanks for contacting us! We will be in touch with you shortly.', 'wpforms-lite' ),
						'message_scroll' => '1',
					],
				],
				'disable_entries'        => $pf_form['pirateformsopt_store'] === 'yes' ? '0' : '1',
				'import_form_id'         => $pf_form_id,
			],
		];

		// Do not save user IP address and UA.
		if ( empty( $pf_form['pirateformsopt_store_ip'] ) || $pf_form['pirateformsopt_store_ip'] !== 'yes' ) {
			$wpforms_settings         = get_option( 'wpforms_settings', [] );
			$wpforms_settings['gdpr'] = true;

			update_option( 'wpforms_settings', $wpforms_settings );

			$form['settings']['disable_ip'] = true;
		}

		// Save recaptcha keys.
		if (
			! empty( $pf_form['pirateformsopt_recaptcha_field'] ) &&
			$pf_form['pirateformsopt_recaptcha_field'] === 'yes'
		) {
			// If the user has already defined v2 reCAPTCHA keys, use those.
			$site_key   = wpforms_setting( 'recaptcha-site-key', '' );
			$secret_key = wpforms_setting( 'recaptcha-secret-key', '' );

			// Try to abstract keys from PF.
			if ( empty( $site_key ) || empty( $secret_key ) ) {
				if ( ! empty( $pf_form['pirateformsopt_recaptcha_sitekey'] ) && ! empty( $pf_form['pirateformsopt_recaptcha_secretkey'] ) ) {
					$wpforms_settings                         = get_option( 'wpforms_settings', [] );
					$wpforms_settings['recaptcha-site-key']   = $pf_form['pirateformsopt_recaptcha_sitekey'];
					$wpforms_settings['recaptcha-secret-key'] = $pf_form['pirateformsopt_recaptcha_secretkey'];
					$wpforms_settings['recaptcha-type']       = 'v2';

					update_option( 'wpforms_settings', $wpforms_settings );
				}
			}

			if (
				( ! empty( $site_key ) && ! empty( $secret_key ) ) ||
				( ! empty( $wpforms_settings['recaptcha-site-key'] ) && ! empty( $wpforms_settings['recaptcha-secret-key'] ) )
			) {
				$form['settings']['recaptcha'] = '1';
			}
		}

		$this->import_smtp( $pf_form_id, $form );

		$this->add_form( $form, $unsupported, $upgrade_plain, $upgrade_omit );
	}

	/**
	 * Replace 3rd-party form provider tags/shortcodes with our own Smart Tags.
	 * See: PirateForms_Util::get_magic_tags() for all PF tags.
	 *
	 * @since 1.6.6
	 *
	 * @param string $string String to process the smart tag in.
	 * @param array  $fields List of fields for the form.
	 *
	 * @return string
	 */
	public function get_smarttags( $string, $fields ) {

		foreach ( self::$tags as $tag ) {
			$wpf_tag = '';

			if ( $tag === '[email]' ) {
				foreach ( $fields as $field ) {
					if ( $field['type'] === 'email' ) {
						$wpf_tag = '{field_id="' . $field['id'] . '"}';

						break;
					}
				}
			}

			$string = str_replace( $tag, $wpf_tag, $string );
		}

		return $string;
	}

	/**
	 * Import SMTP settings from Default form only.
	 *
	 * @since 1.6.6
	 *
	 * @param int   $pf_form_id PirateForms form ID.
	 * @param array $form       WPForms form array.
	 */
	protected function import_smtp( $pf_form_id, $form ) {

		// At this point we import only default form SMTP settings.
		if ( $pf_form_id !== 0 ) {
			return;
		}

		$pf_form = $this->get_form( 0 );

		// Use only if enabled.
		if ( empty( $pf_form['pirateformsopt_use_smtp'] ) || $pf_form['pirateformsopt_use_smtp'] !== 'yes' ) {
			return;
		}

		// If user has WP Mail SMTP already activated - do nothing as it's most likely already configured.
		if ( is_plugin_active( self::SLUG_SMTP_PLUGIN ) ) {
			return;
		}

		// Check that we successfully installed and activated the plugin.
		if ( ! $this->install_activate_smtp() ) {
			return;
		}

		/*
		 * Finally, start the settings importing.
		 */
		// WP Mail SMTP 1.x and PHP 5.3+ are allowed. Older WPMS versions are ignored.
		if ( ! function_exists( 'wp_mail_smtp' ) ) {
			return;
		}

		// TODO: change to \WPMailSMTP\Options in future.
		$options = get_option( 'wp_mail_smtp', [] );

		$options['mail']['from_email'] = $this->get_smarttags( $pf_form['pirateformsopt_email'], $form['fields'] );
		$options['mail']['mailer']     = 'smtp';
		$options['smtp']['host']       = $pf_form['pirateformsopt_smtp_host'];
		$options['smtp']['port']       = $pf_form['pirateformsopt_smtp_port'];
		$options['smtp']['encryption'] = empty( $pf_form['pirateformsopt_use_secure'] ) ? 'none' : $pf_form['pirateformsopt_use_secure'];
		$options['smtp']['auth']       = ! empty( $pf_form['pirateformsopt_use_smtp_authentication'] ) && $pf_form['pirateformsopt_use_smtp_authentication'] === 'yes';
		$options['smtp']['user']       = $pf_form['pirateformsopt_smtp_username'];
		$options['smtp']['pass']       = $pf_form['pirateformsopt_smtp_password'];

		update_option( 'wp_mail_smtp', $options );
	}

	/**
	 * Do all the voodoo to install and activate the WP Mail SMTP plugin behind the scene.
	 * No user interaction is needed.
	 *
	 * @since 1.6.6
	 *
	 * @return bool
	 */
	protected function install_activate_smtp() {
		/*
		 * Check installation.
		 * If installed but not activated - bail.
		 * We don't want to break current site email deliverability.
		 */

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		// FALSE will bail the import.
		if ( array_key_exists( self::SLUG_SMTP_PLUGIN, get_plugins() ) ) {
			return false;
		}

		/*
		 * Let's try to install.
		 */
		$url = add_query_arg(
			[
				'provider' => $this->slug,
				'page'     => 'wpforms-tools',
				'view'     => 'importer',
			],
			admin_url( 'admin.php' )
		);

		$creds = request_filesystem_credentials( esc_url_raw( $url ), '', false, false, null );

		// Check for file system permissions.
		if ( $creds === false ) {
			return false;
		}

		if ( ! WP_Filesystem( $creds ) ) {
			return false;
		}

		// Do not allow WordPress to search/download translations, as this will break JS output.
		remove_action( 'upgrader_process_complete', [ 'Language_Pack_Upgrader', 'async_upgrade' ], 20 );

		// Create the plugin upgrader with our custom skin.
		$installer = new PluginSilentUpgrader( new PluginSilentUpgraderSkin() );

		// Error check.
		if ( ! method_exists( $installer, 'install' ) ) {
			return false;
		}

		$installer->install( self::URL_SMTP_ZIP );

		// Flush the cache and return the newly installed plugin basename.
		wp_cache_flush();

		if ( $installer->plugin_info() ) {
			$plugin_basename = $installer->plugin_info();

			// Activate, do not redirect, run the plugin activation routine.
			$activated = activate_plugin( $plugin_basename );

			if ( ! is_wp_error( $activated ) ) {
				return true;
			}
		}

		return false;
	}
}
