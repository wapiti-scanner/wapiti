<?php

/**
 * Process and validate form entries.
 *
 * @since 1.0.0
 */
class WPForms_Process {

	/**
	 * Store errors.
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	public $errors;

	/**
	 * Confirmation message.
	 *
	 * @var string
	 */
	public $confirmation_message;

	/**
	 * Current confirmation.
	 *
	 * @since 1.6.9
	 *
	 * @var array
	 */
	private $confirmation;

	/**
	 * Store formatted fields.
	 *
	 * @since 1.0.0
	 *
	 * @var array
	 */
	public $fields;

	/**
	 * Store the ID of a successful entry.
	 *
	 * @since 1.2.3
	 *
	 * @var int
	 */
	public $entry_id = 0;

	/**
	 * Form data and settings.
	 *
	 * @since 1.4.5
	 *
	 * @var array
	 */
	public $form_data;

	/**
	 * If a valid return has was processed.
	 *
	 * @since 1.4.5
	 *
	 * @var bool
	 */
	public $valid_hash = false;

	/**
	 * Primary class constructor.
	 *
	 * @since 1.0.0
	 */
	public function __construct() {

		add_action( 'wp', [ $this, 'listen' ] );

		add_action( 'wp_ajax_wpforms_submit', [ $this, 'ajax_submit' ] );
		add_action( 'wp_ajax_nopriv_wpforms_submit', [ $this, 'ajax_submit' ] );
	}

	/**
	 * Listen to see if this is a return callback or a posted form entry.
	 *
	 * @since 1.0.0
	 */
	public function listen() {

		// Catch the post_max_size overflow.
		if ( $this->post_max_size_overflow() ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification
		if ( ! empty( $_GET['wpforms_return'] ) ) {
			// Additional redirect trigger for addons.
			$this->entry_confirmation_redirect( '', sanitize_text_field( wp_unslash( $_GET['wpforms_return'] ) ) );
		}

		$form_id = ! empty( $_POST['wpforms']['id'] ) ? absint( $_POST['wpforms']['id'] ) : 0;

		if ( ! $form_id ) {
			return;
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$this->process( wp_unslash( $_POST['wpforms'] ) );
		// phpcs:enable WordPress.Security.NonceVerification

		if ( ! wpforms_is_amp() ) {
			return;
		}

		// Send 400 Bad Request when there are errors.
		if ( empty( $this->errors[ $form_id ] ) ) {
			wp_send_json(
				[
					'message' => $this->get_confirmation_message( $this->form_data, $this->fields, $this->entry_id ),
				],
				200
			);

			return;
		}

		$message = $this->errors[ $form_id ]['header'];

		if ( ! empty( $this->errors[ $form_id ]['footer'] ) ) {
			$message .= ' ' . $this->errors[ $form_id ]['footer'];
		}

		wp_send_json(
			[
				'message' => $message,
			],
			400
		);
	}

	/**
	 * Process the form entry.
	 *
	 * @since 1.0.0
	 * @since 1.6.4 Added hCaptcha support.
	 *
	 * @param array $entry Form submission raw data ($_POST).
	 */
	public function process( $entry ) {

		$this->errors = [];
		$this->fields = [];

		/* @var int $form_id Annotate the type explicitly. */
		$form_id = absint( $entry['id'] );
		$form    = wpforms()->get( 'form' )->get( $form_id );

		// Validate form is real and active (published).
		if ( ! $form || $form->post_status !== 'publish' ) {
			$this->errors[ $form_id ]['header'] = esc_html__( 'Invalid form.', 'wpforms-lite' );

			return;
		}

		/**
		 * Filter form data obtained during form process.
		 *
		 * @since 1.5.3
		 *
		 * @param array $form_data Form data.
		 * @param array $entry     Form entry.
		 */
		$this->form_data = (array) apply_filters( 'wpforms_process_before_form_data', wpforms_decode( $form->post_content ), $entry );

		if ( ! isset( $this->form_data['fields'], $this->form_data['id'] ) ) {
			$error_id = uniqid();

			// Logs missing form data.
			wpforms_log(
				/* translators: %s - error unique ID. */
				sprintf( esc_html__( 'Missing form data on form submission process %s', 'wpforms-lite' ), $error_id ),
				esc_html__( 'Form data is not an array in `\WPForms_Process::process()`. It might be caused by incorrect data returned by `wpforms_process_before_form_data` filter. Verify whether you have a custom code using this filter and debug value it is returning.', 'wpforms-lite' ),
				[
					'type'    => [ 'error', 'entry' ],
					'form_id' => $form_id,
				]
			);

			$error_messages[] = esc_html__( 'Your form has not been submitted because data is missing from the entry.', 'wpforms-lite' );

			if ( wpforms_setting( 'logs-enable' ) && wpforms_current_user_can( wpforms_get_capability_manage_options() ) ) {
				$error_messages[] = sprintf(
					wp_kses( /* translators: %s - URL to the WForms Logs admin page. */
						__( 'Check the WPForms &raquo; Tools &raquo; <a href="%s">Logs</a> for more details.', 'wpforms-lite' ),
						[ 'a' => [ 'href' => [] ] ]
					),
					esc_url(
						add_query_arg(
							[
								'page' => 'wpforms-tool',
								'view' => 'logs',
							],
							admin_url( 'admin.php' )
						)
					)
				);

				/* translators: %s - error unique ID. */
				$error_messages[] = sprintf( esc_html__( 'Error ID: %s.', 'wpforms-lite' ), $error_id );
			}

			$errors[ $form_id ]['header'] = implode( '<br>', $error_messages );
			$this->errors                 = $errors;

			return;
		}

		// Pre-process/validate hooks and filter.
		// Data is not validated or cleaned yet so use with caution.
		$entry = apply_filters( 'wpforms_process_before_filter', $entry, $this->form_data );

		do_action( 'wpforms_process_before', $entry, $this->form_data );
		do_action( "wpforms_process_before_{$form_id}", $entry, $this->form_data );

		// Validate fields.
		foreach ( $this->form_data['fields'] as $field_properties ) {

			$field_id     = $field_properties['id'];
			$field_type   = $field_properties['type'];
			$field_submit = isset( $entry['fields'][ $field_id ] ) ? $entry['fields'][ $field_id ] : '';

			do_action( "wpforms_process_validate_{$field_type}", $field_id, $field_submit, $this->form_data );
		}

		// CAPTCHA check.
		$captcha_settings = wpforms_get_captcha_settings();
		$bypass_captcha   = apply_filters( 'wpforms_process_bypass_captcha', false, $entry, $this->form_data );

		if (
			! empty( $captcha_settings['provider'] ) &&
			$captcha_settings['provider'] !== 'none' &&
			! empty( $captcha_settings['site_key'] ) &&
			! empty( $captcha_settings['secret_key'] ) &&
			isset( $this->form_data['settings']['recaptcha'] ) &&
			(int) $this->form_data['settings']['recaptcha'] === 1 &&
			empty( $bypass_captcha ) &&
			! isset( $_POST['__amp_form_verify'] ) // phpcs:ignore WordPress.Security.NonceVerification.Missing -- No need to check CAPTCHA until form is submitted.
			&&
			( ( $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'v3' ) || ! wpforms_is_amp() ) // AMP requires Google reCAPTCHA v3.
		) {

			$this->process_captcha( $captcha_settings, $entry );
		}

		// Check if combined upload size exceeds allowed maximum.
		$this->validate_combined_upload_size( $form );

		// Initial error check.
		// Don't proceed if there are any errors thus far. We provide a filter
		// so that other features, such as conditional logic, have the ability
		// to adjust blocking errors.
		$errors = apply_filters( 'wpforms_process_initial_errors', $this->errors, $this->form_data );

		if ( isset( $_POST['__amp_form_verify'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			if ( empty( $errors[ $form_id ] ) ) {
				wp_send_json( [], 200 );
			} else {
				$verify_errors = [];

				foreach ( $errors[ $form_id ] as $field_id => $error_fields ) {
					$field            = $this->form_data['fields'][ $field_id ];
					$field_properties = wpforms()->frontend->get_field_properties( $field, $this->form_data );

					if ( is_string( $error_fields ) ) {

						if ( $field['type'] === 'checkbox' || $field['type'] === 'radio' || $field['type'] === 'select' ) {
							$first = current( $field_properties['inputs'] );
							$name  = $first['attr']['name'];
						} elseif ( isset( $field_properties['inputs']['primary']['attr']['name'] ) ) {
							$name = $field_properties['inputs']['primary']['attr']['name'];
						}

						$verify_errors[] = [
							'name'    => $name,
							'message' => $error_fields,
						];
					} else {
						foreach ( $error_fields as $error_field => $error_message ) {

							if ( isset( $field_properties['inputs'][ $error_field ]['attr']['name'] ) ) {
								$name = $field_properties['inputs'][ $error_field ]['attr']['name'];
							}

							$verify_errors[] = [
								'name'    => $name,
								'message' => $error_message,
							];
						}
					}
				}

				wp_send_json(
					[
						'verifyErrors' => $verify_errors,
					],
					400
				);
			}

			return;
		}

		if ( ! empty( $errors[ $form_id ] ) ) {

			if ( empty( $errors[ $form_id ]['header'] ) && empty( $errors[ $form_id ]['footer'] ) ) {
				$errors[ $form_id ]['header'] = esc_html__( 'Form has not been submitted, please see the errors below.', 'wpforms-lite' );
			}

			$this->errors = $errors;

			return;
		}

		// If a logged-in user fails the nonce check, we want to log the entry, disable the errors and fail silently.
		// Please note that logs may be disabled and in this case nothing will be logged or reported.
		if (
			is_user_logged_in() &&
			( empty( $entry['nonce'] ) || ! wp_verify_nonce( $entry['nonce'], "wpforms::form_{$form_id}" ) )
		) {
			// Logs XSS attempt depending on log levels set.
			wpforms_log(
				'Cross-site scripting attempt ' . uniqid( '', true ),
				[ true, $entry ],
				[
					'type'    => [ 'security' ],
					'form_id' => $this->form_data['id'],
				]
			);

			// Fail silently.
			return;
		}

		$honeypot = wpforms()->get( 'honeypot' )->validate( $this->form_data, $this->fields, $entry );

		// If we trigger the honey pot, we want to log the entry, disable the errors, and fail silently.
		if ( $honeypot ) {

			// Logs spam entry depending on log levels set.
			wpforms_log(
				'Spam Entry ' . uniqid(),
				[ $honeypot, $entry ],
				[
					'type'    => [ 'spam' ],
					'form_id' => $this->form_data['id'],
				]
			);

			// Fail silently.
			return;
		}

		$antispam = wpforms()->get( 'token' )->validate( $this->form_data, $this->fields, $entry );

		// If spam - return early.
		// For antispam, we want to make sure that we have a value, we are not using AMP, and the value is an error string.
		if ( $antispam && ! wpforms_is_amp() && is_string( $antispam ) ) {

			$this->errors[ $form_id ]['header'] = $antispam;

			// Logs spam entry depending on log levels set.
			wpforms_log(
				esc_html__( 'Spam Entry ' ) . uniqid(),
				[ $antispam, $entry ],
				[
					'type'    => [ 'spam' ],
					'form_id' => $this->form_data['id'],
				]
			);

			return;
		}

		$akismet = wpforms()->get( 'akismet' )->validate( $this->form_data, $entry );

		// If Akismet marks the entry as spam, we want to log the entry and fail silently.
		if ( $akismet ) {

			$this->errors[ $form_id ]['header'] = $akismet;

			// Log the spam entry depending on log levels set.
			wpforms_log(
				'Spam Entry ' . uniqid(),
				[ $akismet, $entry ],
				[
					'type'    => [ 'spam' ],
					'form_id' => $this->form_data['id'],
				]
			);

			// Fail silently.
			return;
		}

		// Pass the form created date into the form data.
		$this->form_data['created'] = $form->post_date;

		// Format fields.
		foreach ( (array) $this->form_data['fields'] as $field_properties ) {

			$field_id     = $field_properties['id'];
			$field_type   = $field_properties['type'];
			$field_submit = isset( $entry['fields'][ $field_id ] ) ? $entry['fields'][ $field_id ] : '';

			do_action( "wpforms_process_format_{$field_type}", $field_id, $field_submit, $this->form_data );
		}

		// This hook is for internal purposes and should not be leveraged.
		do_action( 'wpforms_process_format_after', $this->form_data );

		// Process hooks/filter - this is where most addons should hook
		// because at this point we have completed all field validation and
		// formatted the data.
		$this->fields = apply_filters( 'wpforms_process_filter', $this->fields, $entry, $this->form_data );

		do_action( 'wpforms_process', $this->fields, $entry, $this->form_data );
		do_action( "wpforms_process_{$form_id}", $this->fields, $entry, $this->form_data );

		$this->fields = apply_filters( 'wpforms_process_after_filter', $this->fields, $entry, $this->form_data );

		// One last error check - don't proceed if there are any errors.
		if ( ! empty( $this->errors[ $form_id ] ) ) {

			if ( empty( $this->errors[ $form_id ]['header'] ) && empty( $this->errors[ $form_id ]['footer'] ) ) {
				$this->errors[ $form_id ]['header'] = esc_html__( 'Form has not been submitted, please see the errors below.', 'wpforms-lite' );
			}

			return;
		}

		// Success - add entry to database.
		$this->entry_id = $this->entry_save( $this->fields, $entry, $this->form_data['id'], $this->form_data );

		/**
		 * Runs right after adding entry to the database.
		 *
		 * @since 1.7.7
		 *
		 * @param array $fields    Fields data.
		 * @param array $entry     User submitted data.
		 * @param array $form_data Form data.
		 * @param int   $entry_id  Entry ID.
		 */
		do_action( 'wpforms_process_entry_saved', $this->fields, $entry, $this->form_data, $this->entry_id );

		// Fire the logic to send notification emails.
		$this->entry_email( $this->fields, $entry, $this->form_data, $this->entry_id, 'entry' );

		// Pass completed and formatted fields in POST.
		$_POST['wpforms']['complete'] = $this->fields;

		// Pass entry ID in POST.
		$_POST['wpforms']['entry_id'] = $this->entry_id;

		// Logs entry depending on log levels set.
		if ( wpforms()->is_pro() ) {
			wpforms_log(
				$this->entry_id ? "Entry {$this->entry_id}" : 'Entry',
				$this->fields,
				[
					'type'    => [ 'entry' ],
					'parent'  => $this->entry_id,
					'form_id' => $this->form_data['id'],
				]
			);
		}

		// Post-process hooks.
		do_action( 'wpforms_process_complete', $this->fields, $entry, $this->form_data, $this->entry_id );
		do_action( "wpforms_process_complete_{$form_id}", $this->fields, $entry, $this->form_data, $this->entry_id );

		$this->entry_confirmation_redirect( $this->form_data );
	}

	/**
	 * Process captcha.
	 *
	 * @since 1.8.0
	 *
	 * @param array $captcha_settings Captcha settings.
	 * @param array $entry            Form submission raw data ($_POST).
	 *
	 * @return void
	 */
	private function process_captcha( $captcha_settings, $entry ) { // phpcs:ignore Generic.Metrics.CyclomaticComplexity.MaxExceeded

		$form_id = absint( $entry['id'] );
		$captcha = [
			'hcaptcha'  => [
				'verify_url_raw' => 'https://hcaptcha.com/siteverify',
				'provider'       => 'hCaptcha',
				'post_key'       => 'h-captcha-response',
			],
			'recaptcha' => [
				'verify_url_raw' => 'https://www.google.com/recaptcha/api/siteverify',
				'provider'       => 'Google reCAPTCHA',
				'post_key'       => 'g-recaptcha-response',
			],
			'turnstile' => [
				'verify_url_raw' => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
				'provider'       => 'Cloudflare Turnstile',
				'post_key'       => 'cf-turnstile-response', // The key is specified by the API.
			],
		];

		$current_captcha = $captcha[ $captcha_settings['provider'] ];

		$verify_url_raw   = ! empty( $current_captcha ) ? $current_captcha['verify_url_raw'] : '';
		$captcha_provider = ! empty( $current_captcha ) ? $current_captcha['provider'] : '';
		$post_key         = ! empty( $current_captcha ) ? $current_captcha['post_key'] : '';

		/* translators: %s - The CAPTCHA provider name. */
		$error = wpforms_setting( "{$captcha_settings['provider']}-fail-msg", sprintf( esc_html__( '%s verification failed, please try again later.', 'wpforms-lite' ), $captcha_provider ) );

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Missing
		$token = ! empty( $_POST[ $post_key ] ) ? $_POST[ $post_key ] : false;

		$is_recaptcha_v3 = $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'v3';

		if ( $is_recaptcha_v3 ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.NonceVerification.Missing
			$token = ! empty( $_POST['wpforms']['recaptcha'] ) ? $_POST['wpforms']['recaptcha'] : false;
		}

		$verify_query_arg = [
			'secret'   => $captcha_settings['secret_key'],
			'response' => $token,
			'remoteip' => wpforms_get_ip(),
		];

		/*
		 * hCaptcha uses user IP to better detect bots and their attacks on a form.
		 * Majority of our users have GDPR disabled.
		 * So we remove this data from the request only when it's not needed, depending on wpforms_is_collecting_ip_allowed($this->form_data) check.
		 */
		if ( ! wpforms_is_collecting_ip_allowed( $this->form_data ) ) {
			unset( $verify_query_arg['remoteip'] );
		}

		$verify_url = $captcha_settings['provider'] === 'turnstile' ? $verify_url_raw : add_query_arg( $verify_query_arg, $verify_url_raw );

		/**
		 * Change query arguments for remote call to the captcha API.
		 *
		 * @since 1.8.0
		 *
		 * @param array $verify_query_arg The query arguments for verify URL.
		 * @param array $form_data        Form data and settings.
		 */
		$verify_query_arg = apply_filters( 'wpforms_process_captcha_verify_query_arg', $verify_query_arg, $this->form_data );

		/**
		 * Filter the CAPTCHA verify URL.
		 *
		 * @since 1.6.4
		 * @since 1.8.0 Added $form_data argument.
		 *
		 * @param string $verify_url       The full CAPTCHA verify URL.
		 * @param string $verify_url_raw   The CAPTCHA verify URL without query.
		 * @param array  $verify_query_arg The query arguments for verify URL.
		 * @param array  $form_data        Form data and settings.
		 */
		$verify_url = apply_filters( 'wpforms_process_captcha_verify_url', $verify_url, $verify_url_raw, $verify_query_arg, $this->form_data );

		// Cloudflare Turnstile requires POST call instead of GET.
		if ( $captcha_settings['provider'] === 'turnstile' ) {
			$response = wp_remote_post( $verify_url, [ 'body' => $verify_query_arg ] );
		} else {
			$response = wp_remote_get( $verify_url );
		}

		$response_body = json_decode( wp_remote_retrieve_body( $response ), false );

		if (
			empty( $response_body->success ) ||
			( $is_recaptcha_v3 && $response_body->score <= wpforms_setting( 'recaptcha-v3-threshold', '0.4' ) )
		) {
			if ( $is_recaptcha_v3 ) {
				if ( isset( $response_body->score ) ) {
					$error .= ' (' . esc_html( $response_body->score ) . ')';
				}
				$this->errors[ $form_id ]['footer'] = $error;
			} else {
				$this->errors[ $form_id ]['recaptcha'] = $error;
			}
		}
	}

	/**
	 * Check if combined upload size exceeds allowed maximum.
	 *
	 * @since 1.6.0
	 *
	 * @param \WP_Post $form Form post object.
	 */
	public function validate_combined_upload_size( $form ) {

		$form_id       = (int) $form->ID;
		$upload_fields = wpforms_get_form_fields( $form, [ 'file-upload' ] );

		if ( ! empty( $upload_fields ) && ! empty( $_FILES ) ) {

			// Get $_FILES keys generated by WPForms only.
			$files_keys = preg_filter( '/^/', 'wpforms_' . $form_id . '_', array_keys( $upload_fields ) );

			// Filter uploads without errors. Individual errors are handled by WPForms_Field_File_Upload class.
			$files          = wp_list_filter( wp_array_slice_assoc( $_FILES, $files_keys ), [ 'error' => 0 ] );
			$files_size     = array_sum( wp_list_pluck( $files, 'size' ) );
			$files_size_max = wpforms_max_upload( true );

			if ( $files_size > $files_size_max ) {

				// Add new header error preserving previous ones.
				$this->errors[ $form_id ]['header']  = ! empty( $this->errors[ $form_id ]['header'] ) ? $this->errors[ $form_id ]['header'] . '<br>' : '';
				$this->errors[ $form_id ]['header'] .= esc_html__( 'Uploaded files combined size exceeds allowed maximum.', 'wpforms-lite' );
			}
		}
	}

	/**
	 * Validate the form return hash.
	 *
	 * @since 1.0.0
	 *
	 * @param string $hash Base64-encoded hash of form and entry IDs.
	 *
	 * @return array|false False for invalid or form id.
	 */
	public function validate_return_hash( $hash = '' ) {

		$query_args = base64_decode( $hash );

		parse_str( $query_args, $output );

		// Verify hash matches.
		if ( wp_hash( $output['form_id'] . ',' . $output['entry_id'] ) !== $output['hash'] ) {
			return false;
		}

		// Get lead and verify it is attached to the form we received with it.
		$entry = wpforms()->entry->get( $output['entry_id'], [ 'cap' => false ] );

		if ( empty( $entry->form_id ) ) {
			return false;
		}

		if ( $output['form_id'] !== $entry->form_id ) {
			return false;
		}

		return [
			'form_id'  => absint( $output['form_id'] ),
			'entry_id' => absint( $output['form_id'] ),
			'fields'   => $entry !== null && isset( $entry->fields ) ? $entry->fields : [],
		];
	}

	/**
	 * Check if the confirmation data are valid.
	 *
	 * @since 1.6.4
	 *
	 * @param array $data The confirmation data.
	 *
	 * @return bool
	 */
	protected function is_valid_confirmation( $data ) {

		if ( empty( $data['type'] ) ) {
			return false;
		}

		// Confirmation type: redirect, page or message.
		$type = $data['type'];

		return isset( $data[ $type ] ) && ! wpforms_is_empty_string( $data[ $type ] );
	}

	/**
	 * Redirect user to a page or URL specified in the form confirmation settings.
	 *
	 * @since 1.0.0
	 *
	 * @param array  $form_data Form data and settings.
	 * @param string $hash      Base64-encoded hash of form and entry IDs.
	 */
	public function entry_confirmation_redirect( $form_data = [], $hash = '' ) {

		// Maybe process return hash.
		if ( ! empty( $hash ) ) {

			$hash_data = $this->validate_return_hash( $hash );

			if ( ! $hash_data || ! is_array( $hash_data ) ) {
				return;
			}

			$this->valid_hash = true;
			$this->entry_id   = absint( $hash_data['entry_id'] );
			$this->fields     = json_decode( $hash_data['fields'], true );
			$this->form_data  = wpforms()->form->get(
				absint( $hash_data['form_id'] ),
				[
					'content_only' => true,
				]
			);

		} else {

			$this->form_data = $form_data;
		}

		// Backward compatibility.
		if ( empty( $this->form_data['settings']['confirmations'] ) ) {
			$this->form_data['settings']['confirmations'][1]['type']           = ! empty( $this->form_data['settings']['confirmation_type'] ) ? $this->form_data['settings']['confirmation_type'] : 'message';
			$this->form_data['settings']['confirmations'][1]['message']        = ! empty( $this->form_data['settings']['confirmation_message'] ) ? $this->form_data['settings']['confirmation_message'] : esc_html__( 'Thanks for contacting us! We will be in touch with you shortly.', 'wpforms-lite' );
			$this->form_data['settings']['confirmations'][1]['message_scroll'] = ! empty( $this->form_data['settings']['confirmation_message_scroll'] ) ? $this->form_data['settings']['confirmation_message_scroll'] : 1;
			$this->form_data['settings']['confirmations'][1]['page']           = ! empty( $this->form_data['settings']['confirmation_page'] ) ? $this->form_data['settings']['confirmation_page'] : '';
			$this->form_data['settings']['confirmations'][1]['redirect']       = ! empty( $this->form_data['settings']['confirmation_redirect'] ) ? $this->form_data['settings']['confirmation_redirect'] : '';
		}

		if ( empty( $this->form_data['settings']['confirmations'] ) || ! is_array( $this->form_data['settings']['confirmations'] ) ) {
			return;
		}

		$confirmations = $this->form_data['settings']['confirmations'];

		// Reverse sort confirmations by id to process newer ones first.
		krsort( $confirmations );

		$default_confirmation_key = min( array_keys( $confirmations ) );

		foreach ( $confirmations as $confirmation_id => $confirmation ) {
			// Last confirmation should execute in any case.
			if ( $default_confirmation_key === $confirmation_id ) {
				break;
			}

			if ( ! $this->is_valid_confirmation( $confirmation ) ) {
				continue;
			}

			// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName

			/**
			 * Process confirmation filter.
			 *
			 * @since 1.4.8
			 *
			 * @param bool  $process   Whether to process the logic or not.
			 * @param array $fields    List of submitted fields.
			 * @param array $form_data Form data and settings.
			 * @param int   $id        Confirmation ID.
			 */
			$process_confirmation = apply_filters( 'wpforms_entry_confirmation_process', true, $this->fields, $this->form_data, $confirmation_id );
			// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

			if ( $process_confirmation ) {
				break;
			}
		}

		$url = '';
		// Redirect if needed, to either a page or URL, after form processing.
		if ( ! empty( $confirmations[ $confirmation_id ]['type'] ) && 'message' !== $confirmations[ $confirmation_id ]['type'] ) {

			if ( $confirmations[ $confirmation_id ]['type'] === 'redirect' ) {

				$rawurlencode_callback = static function ( $value ) {
					return $value === null ? null : rawurlencode( $value );
				};

				add_filter( 'wpforms_smarttags_process_field_id_value', $rawurlencode_callback );

				$url = wpforms_process_smart_tags( $confirmations[ $confirmation_id ]['redirect'], $this->form_data, $this->fields, $this->entry_id );

				remove_filter( 'wpforms_smarttags_process_field_id_value', $rawurlencode_callback );
			}

			if ( 'page' === $confirmations[ $confirmation_id ]['type'] ) {
				$url = get_permalink( (int) $confirmations[ $confirmation_id ]['page'] );
			}
		}

		if ( ! empty( $url ) ) {
			$url = apply_filters( 'wpforms_process_redirect_url', $url, $this->form_data['id'], $this->fields, $this->form_data, $this->entry_id );
			if ( wpforms_is_amp() ) {
				/** This filter is documented in wp-includes/pluggable.php */
				$url = apply_filters( 'wp_redirect', $url, 302 );
				$url = wp_sanitize_redirect( $url );
				header( sprintf( 'AMP-Redirect-To: %s', $url ) );
				header( 'Access-Control-Expose-Headers: AMP-Redirect-To', false );
				wp_send_json(
					[
						'message'     => __( 'Redirecting…', 'wpforms-lite' ),
						'redirecting' => true,
					],
					200
				);
			} else {
				wp_redirect( esc_url_raw( $url ) ); // phpcs:ignore
			}
			do_action( 'wpforms_process_redirect', $this->form_data['id'] );
			do_action( "wpforms_process_redirect_{$this->form_data['id']}", $this->form_data['id'] );
			exit;
		}

		// Pass a message to a frontend if no redirection happened.
		if ( ! empty( $confirmations[ $confirmation_id ]['type'] ) && 'message' === $confirmations[ $confirmation_id ]['type'] ) {
			$this->confirmation         = $confirmations[ $confirmation_id ];
			$this->confirmation_message = $confirmations[ $confirmation_id ]['message'];

			if ( ! empty( $confirmations[ $confirmation_id ]['message_scroll'] ) ) {
				wpforms()->frontend->confirmation_message_scroll = true;
			}
		}
	}

	/**
	 * Get confirmation message.
	 *
	 * @since 1.5.3
	 *
	 * @param array $form_data Form data and settings.
	 * @param array $fields    Sanitized field data.
	 * @param int   $entry_id  Entry id.
	 *
	 * @return string Confirmation message.
	 */
	public function get_confirmation_message( $form_data, $fields, $entry_id ) {

		if ( empty( $this->confirmation_message ) ) {
			return '';
		}

		$confirmation_message = wpforms_process_smart_tags( $this->confirmation_message, $form_data, $fields, $entry_id );
		$confirmation_message = apply_filters( 'wpforms_frontend_confirmation_message', wpautop( $confirmation_message ), $form_data, $fields, $entry_id );

		return $confirmation_message;
	}

	/**
	 * Get current confirmation.
	 *
	 * @since 1.6.9
	 *
	 * @return array
	 */
	public function get_current_confirmation() {

		return ! empty( $this->confirmation ) ? $this->confirmation : [];
	}

	/**
	 * Catch the post_max_size overflow.
	 *
	 * @since 1.5.2
	 *
	 * @return bool
	 */
	public function post_max_size_overflow() {

		// phpcs:disable WordPress.Security.NonceVerification
		if ( empty( $_SERVER['CONTENT_LENGTH'] ) || empty( $_GET['wpforms_form_id'] ) ) {
			return false;
		}

		$form_id       = (int) $_GET['wpforms_form_id'];
		$total_size    = (int) $_SERVER['CONTENT_LENGTH'];
		$post_max_size = wpforms_size_to_bytes( ini_get( 'post_max_size' ) );

		if ( ! ( $total_size > $post_max_size && empty( $_POST ) && $form_id > 0 ) ) {
			return false;
		}
		// phpcs:enable WordPress.Security.NonceVerification

		$error_msg  = esc_html__( 'Form has not been submitted, please see the errors below.', 'wpforms-lite' );
		$error_msg .= '<br>' . sprintf( /* translators: %1$.3f - the total size of the selected files in megabytes, %2$.3f - allowed file upload limit in megabytes.*/
			esc_html__( 'The total size of the selected files %1$.3f MB exceeds the allowed limit %2$.3f MB.', 'wpforms-lite' ),
			esc_html( $total_size / 1048576 ),
			esc_html( $post_max_size / 1048576 )
		);

		$this->errors[ $form_id ]['header'] = $error_msg;

		return true;
	}

	/**
	 * Send entry email notifications.
	 *
	 * @since 1.0.0
	 *
	 * @param array  $fields    List of fields.
	 * @param array  $entry     Submitted form entry.
	 * @param array  $form_data Form data and settings.
	 * @param int    $entry_id  Saved entry id.
	 * @param string $context   In which context this email is sent.
	 */
	public function entry_email( $fields, $entry, $form_data, $entry_id, $context = '' ) {

		// Check that the form was configured for email notifications.
		if ( empty( $form_data['settings']['notification_enable'] ) ) {
			return;
		}

		// Provide the opportunity to override via a filter.
		if ( ! apply_filters( 'wpforms_entry_email', true, $fields, $entry, $form_data ) ) {
			return;
		}

		// Make sure we have and entry id.
		if ( empty( $this->entry_id ) ) {
			$this->entry_id = (int) $entry_id;
		}

		$fields = apply_filters( 'wpforms_entry_email_data', $fields, $entry, $form_data );

		// Backwards compatibility for notifications before v1.4.3.
		if ( empty( $form_data['settings']['notifications'] ) && ! empty( $form_data['settings']['notification_email'] ) ) {
			$notifications[1] = [
				'email'          => $form_data['settings']['notification_email'],
				'subject'        => $form_data['settings']['notification_subject'],
				'sender_name'    => $form_data['settings']['notification_fromname'],
				'sender_address' => $form_data['settings']['notification_fromaddress'],
				'replyto'        => $form_data['settings']['notification_replyto'],
				'message'        => '{all_fields}',
			];
		} else {
			$notifications = $form_data['settings']['notifications'];
		}

		foreach ( $notifications as $notification_id => $notification ) :

			if ( empty( $notification['email'] ) ) {
				continue;
			}

			$process_email = apply_filters( 'wpforms_entry_email_process', true, $fields, $form_data, $notification_id, $context );

			if ( ! $process_email ) {
				continue;
			}

			$email = [];

			// Setup email properties.
			/* translators: %s - form name. */
			$email['subject']        = ! empty( $notification['subject'] ) ? $notification['subject'] : sprintf( esc_html__( 'New %s Entry', 'wpforms-lite' ), $form_data['settings']['form_title'] );
			$email['address']        = explode( ',', wpforms_process_smart_tags( $notification['email'], $form_data, $fields, $this->entry_id ) );
			$email['address']        = array_map( 'sanitize_email', $email['address'] );
			$email['sender_address'] = ! empty( $notification['sender_address'] ) ? $notification['sender_address'] : get_option( 'admin_email' );
			$email['sender_name']    = ! empty( $notification['sender_name'] ) ? $notification['sender_name'] : get_bloginfo( 'name' );
			$email['replyto']        = ! empty( $notification['replyto'] ) ? $notification['replyto'] : false;
			$email['message']        = ! empty( $notification['message'] ) ? $notification['message'] : '{all_fields}';
			$email                   = apply_filters( 'wpforms_entry_email_atts', $email, $fields, $entry, $form_data, $notification_id );

			// Create new email.
			$emails = new WPForms_WP_Emails();
			$emails->__set( 'form_data', $form_data );
			$emails->__set( 'fields', $fields );
			$emails->__set( 'notification_id', $notification_id );
			$emails->__set( 'entry_id', $this->entry_id );
			$emails->__set( 'from_name', $email['sender_name'] );
			$emails->__set( 'from_address', $email['sender_address'] );
			$emails->__set( 'reply_to', $email['replyto'] );

			// Maybe include CC.
			if ( ! empty( $notification['carboncopy'] ) && wpforms_setting( 'email-carbon-copy', false ) ) {
				$emails->__set( 'cc', $notification['carboncopy'] );
			}

			$emails = apply_filters( 'wpforms_entry_email_before_send', $emails );

			// Go.
			foreach ( $email['address'] as $address ) {
				$emails->send( trim( $address ), $email['subject'], $email['message'] );
			}
		endforeach;
	}

	/**
	 * Save entry to database.
	 *
	 * @since 1.0.0
	 *
	 * @param array $fields    List of form fields.
	 * @param array $entry     User submitted data.
	 * @param int   $form_id   Form ID.
	 * @param array $form_data Prepared form settings.
	 *
	 * @return int
	 */
	public function entry_save( $fields, $entry, $form_id, $form_data = [] ) {

		do_action( 'wpforms_process_entry_save', $fields, $entry, $form_id, $form_data );

		return $this->entry_id;
	}

	/**
	 * Process AJAX form submit.
	 *
	 * @since 1.5.3
	 */
	public function ajax_submit() {

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$form_id = isset( $_POST['wpforms']['id'] ) ? absint( $_POST['wpforms']['id'] ) : 0;

		if ( empty( $form_id ) ) {
			wp_send_json_error();
		}

		if ( isset( $_POST['wpforms']['post_id'] ) ) {
			// We don't have a global $post when processing ajax requests.
			// Therefore, it's needed to set a global $post manually for compatibility with functions used in smart tag processing.
			global $post;
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
			$post = WP_Post::get_instance( absint( $_POST['wpforms']['post_id'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		add_filter( 'wp_redirect', [ $this, 'ajax_process_redirect' ], 999 );

		do_action( 'wpforms_ajax_submit_before_processing', $form_id );

		// If redirect happens in listen(), ajax_process_redirect() gets executed because of the filter on `wp_redirect`.
		// The code, that is below listen(), runs only if no redirect happened.
		$this->listen();

		$form_data = $this->form_data;

		if ( empty( $form_data ) ) {
			$form_data = wpforms()->form->get( $form_id, [ 'content_only' => true ] );
			$form_data = apply_filters( 'wpforms_frontend_form_data', $form_data );
		}

		if ( ! empty( $this->errors[ $form_id ] ) ) {
			$this->ajax_process_errors( $form_id, $form_data );
			wp_send_json_error();
		}

		ob_start();

		wpforms()->frontend->confirmation( $form_data );

		$response = apply_filters( 'wpforms_ajax_submit_success_response', [ 'confirmation' => ob_get_clean() ], $form_id, $form_data );

		do_action( 'wpforms_ajax_submit_completed', $form_id, $response );

		wp_send_json_success( $response );
	}

	/**
	 * Process AJAX errors.
	 *
	 * @since 1.5.3
	 * @todo This should be re-used/combined for AMP verify-xhr requests.
	 *
	 * @param int   $form_id   Form ID.
	 * @param array $form_data Form data and settings.
	 */
	protected function ajax_process_errors( $form_id, $form_data ) {

		$errors = isset( $this->errors[ $form_id ] ) ? $this->errors[ $form_id ] : [];

		$errors = apply_filters( 'wpforms_ajax_submit_errors', $errors, $form_id, $form_data );

		if ( empty( $errors ) ) {
			wp_send_json_error();
		}

		// General errors are errors that cannot be populated with jQuery Validate plugin.
		$general_errors = array_intersect_key( $errors, array_flip( [ 'header', 'footer', 'recaptcha' ] ) );

		foreach ( $general_errors as $key => $error ) {
			ob_start();
			wpforms()->get( 'frontend' )->form_error( $key, $error, $form_data );
			$general_errors[ $key ] = ob_get_clean();
		}

		$fields = isset( $form_data['fields'] ) ? $form_data['fields'] : [];

		// Get registered fields errors only.
		$field_errors = array_intersect_key( $errors, $fields );

		// Transform field ids to field names for jQuery Validate plugin.
		foreach ( $field_errors as $key => $error ) {

			$name = $this->ajax_error_field_name( $fields[ $key ], $form_data, $error );
			if ( $name ) {
				$field_errors[ $name ] = $error;
			}

			unset( $field_errors[ $key ] );
		}

		$response = [];

		if ( $general_errors ) {
			$response['errors']['general'] = $general_errors;
		}

		if ( $field_errors ) {
			$response['errors']['field'] = $field_errors;
		}

		$response = apply_filters( 'wpforms_ajax_submit_errors_response', $response, $form_id, $form_data );

		do_action( 'wpforms_ajax_submit_completed', $form_id, $response );

		wp_send_json_error( $response );
	}

	/**
	 * Get field name for ajax error message.
	 *
	 * @since 1.6.3
	 *
	 * @param array  $field     Field settings.
	 * @param array  $form_data Form data and settings.
	 * @param string $error     Error message.
	 *
	 * @return string
	 */
	private function ajax_error_field_name( $field, $form_data, $error ) {

		$props = wpforms()->frontend->get_field_properties( $field, $form_data );

		return apply_filters( 'wpforms_process_ajax_error_field_name', '', $field, $props, $error );
	}

	/**
	 * Process AJAX redirect.
	 *
	 * @since 1.5.3
	 *
	 * @param string $url Redirect URL.
	 */
	public function ajax_process_redirect( $url ) {

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$form_id = isset( $_POST['wpforms']['id'] ) ? absint( $_POST['wpforms']['id'] ) : 0;

		if ( empty( $form_id ) ) {
			wp_send_json_error();
		}

		$response = [
			'form_id'      => $form_id,
			'redirect_url' => $url,
		];

		$response = apply_filters( 'wpforms_ajax_submit_redirect', $response, $form_id, $url );

		do_action( 'wpforms_ajax_submit_completed', $form_id, $response );

		wp_send_json_success( $response );
	}
}
